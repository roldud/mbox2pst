//! Lists, Tables and Properties (LTP) layer ([MS-PST] section 2.3).
//!
//! Builds Heap-on-Node (HN) structures, BTree-on-Heap (BTH), Property
//! Contexts (PC) and Table Contexts (TC) into `NodeContent` values that the
//! NDB layer can write.

use crate::ndb::{NodeContent, SubNode, MAX_BLOCK_DATA};

/// Largest single heap allocation; bigger values go to a subnode.
const MAX_HEAP_ALLOC: usize = 3580;

pub const PT_I16: u16 = 0x0002;
pub const PT_I32: u16 = 0x0003;
pub const PT_BOOL: u16 = 0x000B;
pub const PT_I64: u16 = 0x0014;
pub const PT_STRING: u16 = 0x001F;
pub const PT_TIME: u16 = 0x0040;
pub const PT_BINARY: u16 = 0x0102;
pub const PT_MV_I32: u16 = 0x1003;

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub enum Value {
    I16(i16),
    I32(i32),
    Bool(bool),
    I64(i64),
    Time(u64),
    Str(String),
    Bin(Vec<u8>),
}

impl Value {
    pub fn ptype(&self) -> u16 {
        match self {
            Value::I16(_) => PT_I16,
            Value::I32(_) => PT_I32,
            Value::Bool(_) => PT_BOOL,
            Value::I64(_) => PT_I64,
            Value::Time(_) => PT_TIME,
            Value::Str(_) => PT_STRING,
            Value::Bin(_) => PT_BINARY,
        }
    }
    /// Size of the value as Outlook counts it (e.g. for PR_ATTACH_SIZE):
    /// fixed-size types by their width, strings and binaries by byte length.
    pub fn byte_size(&self) -> usize {
        match self {
            Value::I16(_) => 2,
            Value::I32(_) => 4,
            Value::Bool(_) => 1,
            Value::I64(_) | Value::Time(_) => 8,
            Value::Str(s) => s.encode_utf16().count() * 2,
            Value::Bin(b) => b.len(),
        }
    }
    fn var_bytes(&self) -> Option<Vec<u8>> {
        match self {
            Value::Str(s) => Some(utf16le(s)),
            Value::Bin(b) => Some(b.clone()),
            Value::I64(v) => Some(v.to_le_bytes().to_vec()),
            Value::Time(v) => Some(v.to_le_bytes().to_vec()),
            _ => None,
        }
    }
}

pub fn utf16le(s: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(s.len() * 2);
    for u in s.encode_utf16() {
        v.extend_from_slice(&u.to_le_bytes());
    }
    v
}

/// A property list: (property id, value).
pub type PropList = Vec<(u16, Value)>;

// ---------------------------------------------------------------------------
// Heap-on-Node
// ---------------------------------------------------------------------------

struct HeapPage {
    allocs: Vec<Vec<u8>>,
    used: usize,
}

pub struct Heap {
    client_sig: u8,
    user_root: u32,
    pages: Vec<HeapPage>,
}

fn page_header_size(index: usize) -> usize {
    if index == 0 {
        12 // HNHDR
    } else if index >= 8 && (index - 8) % 128 == 0 {
        66 // HNBITMAPHDR
    } else {
        2 // HNPAGEHDR
    }
}

fn fill_level(free: usize) -> u8 {
    const LEVELS: [usize; 15] = [3584, 2560, 2048, 1792, 1536, 1280, 1024, 768, 512, 256, 128, 64, 32, 16, 8];
    for (i, &l) in LEVELS.iter().enumerate() {
        if free >= l {
            return i as u8;
        }
    }
    0x0F
}

impl Heap {
    pub fn new(client_sig: u8) -> Self {
        Heap { client_sig, user_root: 0, pages: Vec::new() }
    }

    fn page_bytes(index: usize, used: usize, n_allocs: usize) -> usize {
        let body = page_header_size(index) + used;
        (body + 1) / 2 * 2 + 4 + 2 * (n_allocs + 1)
    }

    /// Allocate `data` on the heap and return its HID.
    pub fn alloc(&mut self, data: Vec<u8>) -> u32 {
        assert!(data.len() <= MAX_HEAP_ALLOC);
        let fits = |idx: usize, p: &HeapPage| {
            p.allocs.len() < 2047 && Self::page_bytes(idx, p.used + data.len(), p.allocs.len() + 1) <= MAX_BLOCK_DATA
        };
        let need_new = match self.pages.last() {
            None => true,
            Some(p) => !fits(self.pages.len() - 1, p),
        };
        if need_new {
            self.pages.push(HeapPage { allocs: Vec::new(), used: 0 });
        }
        let block = self.pages.len() - 1;
        let page = self.pages.last_mut().unwrap();
        page.used += data.len();
        page.allocs.push(data);
        ((block as u32) << 16) | ((page.allocs.len() as u32) << 5)
    }

    pub fn set_user_root(&mut self, hid: u32) {
        self.user_root = hid;
    }

    /// Serialise the heap into data blocks.
    pub fn into_blocks(self) -> Vec<Vec<u8>> {
        let mut pages = self.pages;
        if pages.is_empty() {
            pages.push(HeapPage { allocs: Vec::new(), used: 0 });
        }
        let fills: Vec<u8> = pages
            .iter()
            .enumerate()
            .map(|(i, p)| fill_level(MAX_BLOCK_DATA - Self::page_bytes(i, p.used, p.allocs.len())))
            .collect();
        let mut blocks = Vec::with_capacity(pages.len());
        let last = pages.len() - 1;
        for (i, p) in pages.iter().enumerate() {
            let hsize = page_header_size(i);
            let mut buf = vec![0u8; hsize];
            let mut offsets = Vec::with_capacity(p.allocs.len() + 1);
            for a in &p.allocs {
                offsets.push(buf.len() as u16);
                buf.extend_from_slice(a);
            }
            offsets.push(buf.len() as u16);
            let map_size = 4 + 2 * (p.allocs.len() + 1);
            // Outlook requires all blocks of a multi-block node but the last to be
            // full; the page map always ends at the end of the block.
            let target = if i < last { MAX_BLOCK_DATA - map_size } else { (buf.len() + 1) / 2 * 2 };
            buf.resize(target, 0);
            let ib_hnpm = buf.len() as u16;
            buf.extend_from_slice(&(p.allocs.len() as u16).to_le_bytes()); // cAlloc
            buf.extend_from_slice(&0u16.to_le_bytes()); // cFree
            for o in offsets {
                buf.extend_from_slice(&o.to_le_bytes());
            }
            buf[0..2].copy_from_slice(&ib_hnpm.to_le_bytes());
            let pack = |buf: &mut Vec<u8>, at: usize, first: usize, count: usize| {
                for k in 0..count {
                    let lvl = fills.get(first + k).copied().unwrap_or(0);
                    buf[at + k / 2] |= if k % 2 == 0 { lvl } else { lvl << 4 };
                }
            };
            if i == 0 {
                buf[2] = 0xEC; // bSig
                buf[3] = self.client_sig;
                buf[4..8].copy_from_slice(&self.user_root.to_le_bytes());
                pack(&mut buf, 8, 0, 8);
            } else if hsize == 66 {
                pack(&mut buf, 2, i, 128);
            }
            debug_assert!(buf.len() <= MAX_BLOCK_DATA && (i == last || buf.len() == MAX_BLOCK_DATA));
            blocks.push(buf);
        }
        blocks
    }
}

// ---------------------------------------------------------------------------
// BTree-on-Heap
// ---------------------------------------------------------------------------

/// Build a BTH from records sorted by key; returns the HID of the BTHHEADER.
fn build_bth(heap: &mut Heap, cb_key: usize, cb_ent: usize, records: &[(Vec<u8>, Vec<u8>)]) -> u32 {
    let mut levels: u8 = 0;
    let mut root: u32 = 0;
    if !records.is_empty() {
        let per_leaf = MAX_HEAP_ALLOC / (cb_key + cb_ent);
        let mut nodes: Vec<(Vec<u8>, u32)> = Vec::new();
        for chunk in records.chunks(per_leaf) {
            let mut buf = Vec::with_capacity(chunk.len() * (cb_key + cb_ent));
            for (k, d) in chunk {
                buf.extend_from_slice(k);
                buf.extend_from_slice(d);
            }
            nodes.push((chunk[0].0.clone(), heap.alloc(buf)));
        }
        let per_index = MAX_HEAP_ALLOC / (cb_key + 4);
        while nodes.len() > 1 {
            levels += 1;
            let mut next = Vec::new();
            for chunk in nodes.chunks(per_index) {
                let mut buf = Vec::new();
                for (k, hid) in chunk {
                    buf.extend_from_slice(k);
                    buf.extend_from_slice(&hid.to_le_bytes());
                }
                next.push((chunk[0].0.clone(), heap.alloc(buf)));
            }
            nodes = next;
        }
        root = nodes[0].1;
    }
    let mut hdr = vec![0xB5, cb_key as u8, cb_ent as u8, levels];
    hdr.extend_from_slice(&root.to_le_bytes());
    heap.alloc(hdr)
}

/// Allocates subnode NIDs for values too large for the heap.
struct SubnodeAlloc {
    next: u32,
    nodes: Vec<SubNode>,
}

impl SubnodeAlloc {
    fn new() -> Self {
        SubnodeAlloc { next: 0x400, nodes: Vec::new() }
    }
    /// Store bytes on the heap or in a subnode; returns the HNID.
    fn store(&mut self, heap: &mut Heap, bytes: Vec<u8>) -> u32 {
        if bytes.len() <= MAX_HEAP_ALLOC {
            heap.alloc(bytes)
        } else {
            let nid = (self.next << 5) | 0x1F; // NID_TYPE_LTP
            self.next += 1;
            self.nodes.push(SubNode { nid, content: NodeContent::from_stream(&bytes) });
            nid
        }
    }
}

// ---------------------------------------------------------------------------
// Property Context
// ---------------------------------------------------------------------------

/// Build a Property Context node. `extra` subnodes (e.g. recipient table,
/// attachments) are appended to the node's subnode list.
pub fn build_pc(props: &PropList, extra: Vec<SubNode>) -> NodeContent {
    let mut heap = Heap::new(0xBC);
    let mut subs = SubnodeAlloc::new();
    let mut sorted: Vec<&(u16, Value)> = props.iter().collect();
    sorted.sort_by_key(|(id, _)| *id);
    sorted.dedup_by_key(|(id, _)| *id);
    let mut records = Vec::with_capacity(sorted.len());
    for (id, v) in sorted {
        let dw: u32 = match v {
            Value::I16(x) => *x as u16 as u32,
            Value::I32(x) => *x as u32,
            Value::Bool(b) => *b as u32,
            other => subs.store(&mut heap, other.var_bytes().unwrap()),
        };
        let mut data = Vec::with_capacity(6);
        data.extend_from_slice(&v.ptype().to_le_bytes());
        data.extend_from_slice(&dw.to_le_bytes());
        records.push((id.to_le_bytes().to_vec(), data));
    }
    let root = build_bth(&mut heap, 2, 6, &records);
    heap.set_user_root(root);
    let mut subnodes = subs.nodes;
    subnodes.extend(extra);
    NodeContent { blocks: heap.into_blocks(), subnodes }
}

// ---------------------------------------------------------------------------
// Table Context
// ---------------------------------------------------------------------------

pub struct TableRow {
    pub row_id: u32,
    pub values: Vec<(u16, Value)>,
}

struct ColDesc {
    tag: u32,
    ib: u16,
    cb: u8,
    ibit: u8,
}

const PID_LTP_ROW_ID: u16 = 0x67F2;
const PID_LTP_ROW_VER: u16 = 0x67F3;

/// Build a Table Context. `columns` lists (prop id, prop type) for every
/// column besides the mandatory row id / row version columns.
pub fn build_tc(columns: &[(u16, u16)], rows: &[TableRow]) -> NodeContent {
    let mut heap = Heap::new(0x7C);
    let mut subs = SubnodeAlloc::new();

    // Column layout: row id, row version, 8-byte, 4-byte, 2-byte, 1-byte, CEB.
    let size_of = |t: u16| match t {
        0x0005 | 0x0006 | 0x0007 | PT_I64 | PT_TIME => 8, // double, currency, apptime, int64, time
        0x0002 => 2,
        PT_BOOL => 1,
        _ => 4, // int32, float, error code, and every variable-size type (HNID)
    };
    let mut cols: Vec<ColDesc> = vec![
        ColDesc { tag: ((PID_LTP_ROW_ID as u32) << 16) | PT_I32 as u32, ib: 0, cb: 4, ibit: 0 },
        ColDesc { tag: ((PID_LTP_ROW_VER as u32) << 16) | PT_I32 as u32, ib: 4, cb: 4, ibit: 1 },
    ];
    let mut off: u16 = 8;
    let mut ibit: u8 = 2;
    let mut ends = [0u16; 3];
    for (gi, sizes) in [&[8usize, 4][..], &[2][..], &[1][..]].iter().enumerate() {
        for &sz in sizes.iter() {
            for &(id, t) in columns {
                if size_of(t) == sz {
                    cols.push(ColDesc { tag: ((id as u32) << 16) | t as u32, ib: off, cb: sz as u8, ibit });
                    off += sz as u16;
                    ibit += 1;
                }
            }
        }
        ends[gi] = off;
    }
    let ceb_size = (cols.len() + 7) / 8;
    let row_size = off as usize + ceb_size;

    // Row matrix.
    let mut matrix = Vec::with_capacity(rows.len() * row_size);
    for (index, row) in rows.iter().enumerate() {
        let mut r = vec![0u8; row_size];
        let set_bit = |r: &mut Vec<u8>, bit: u8| r[off as usize + bit as usize / 8] |= 0x80 >> (bit % 8);
        r[0..4].copy_from_slice(&row.row_id.to_le_bytes());
        r[4..8].copy_from_slice(&(index as u32 + 1).to_le_bytes());
        set_bit(&mut r, 0);
        set_bit(&mut r, 1);
        for (id, v) in &row.values {
            let Some(c) = cols.iter().find(|c| (c.tag >> 16) as u16 == *id && (c.tag & 0xFFFF) as u16 == v.ptype())
            else {
                continue;
            };
            let at = c.ib as usize;
            match v {
                Value::I16(x) => r[at..at + 2].copy_from_slice(&x.to_le_bytes()),
                Value::I32(x) => r[at..at + 4].copy_from_slice(&x.to_le_bytes()),
                Value::Bool(b) => r[at] = *b as u8,
                Value::I64(x) => r[at..at + 8].copy_from_slice(&x.to_le_bytes()),
                Value::Time(x) => r[at..at + 8].copy_from_slice(&x.to_le_bytes()),
                Value::Str(_) | Value::Bin(_) => {
                    let hnid = subs.store(&mut heap, v.var_bytes().unwrap());
                    r[at..at + 4].copy_from_slice(&hnid.to_le_bytes());
                }
            }
            set_bit(&mut r, c.ibit);
        }
        matrix.extend_from_slice(&r);
    }
    let hnid_rows: u32 = if rows.is_empty() {
        0
    } else if matrix.len() <= MAX_HEAP_ALLOC {
        heap.alloc(matrix)
    } else {
        // Rows must not straddle block boundaries.
        let per_block = MAX_BLOCK_DATA / row_size;
        let chunks: Vec<&[u8]> = matrix.chunks(per_block * row_size).collect();
        let n = chunks.len();
        let blocks: Vec<Vec<u8>> = chunks
            .into_iter()
            .enumerate()
            .map(|(k, c)| {
                let mut b = c.to_vec();
                if k + 1 < n {
                    b.resize(MAX_BLOCK_DATA, 0);
                }
                b
            })
            .collect();
        let nid = (subs.next << 5) | 0x1F;
        subs.next += 1;
        subs.nodes.push(SubNode { nid, content: NodeContent { blocks, subnodes: Vec::new() } });
        nid
    };

    // Row index: row id -> row index.
    let mut index: Vec<(Vec<u8>, Vec<u8>)> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.row_id.to_le_bytes().to_vec(), (i as u32).to_le_bytes().to_vec()))
        .collect();
    index.sort_by_key(|(k, _)| u32::from_le_bytes([k[0], k[1], k[2], k[3]]));
    let hid_row_index = build_bth(&mut heap, 4, 4, &index);

    cols.sort_by_key(|c| c.tag);
    let mut info = Vec::with_capacity(22 + cols.len() * 8);
    info.push(0x7C);
    info.push(cols.len() as u8);
    info.extend_from_slice(&ends[0].to_le_bytes()); // TCI_4b
    info.extend_from_slice(&ends[1].to_le_bytes()); // TCI_2b
    info.extend_from_slice(&ends[2].to_le_bytes()); // TCI_1b
    info.extend_from_slice(&(row_size as u16).to_le_bytes()); // TCI_bm
    info.extend_from_slice(&hid_row_index.to_le_bytes());
    info.extend_from_slice(&hnid_rows.to_le_bytes());
    info.extend_from_slice(&0u32.to_le_bytes()); // hidIndex (deprecated)
    for c in &cols {
        info.extend_from_slice(&c.tag.to_le_bytes());
        info.extend_from_slice(&c.ib.to_le_bytes());
        info.push(c.cb);
        info.push(c.ibit);
    }
    let root = heap.alloc(info);
    heap.set_user_root(root);
    NodeContent { blocks: heap.into_blocks(), subnodes: subs.nodes }
}
