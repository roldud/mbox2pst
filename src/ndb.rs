//! Node Database (NDB) layer of a Unicode PST file ([MS-PST] section 2.2).
//!
//! The writer streams blocks to disk sequentially as they are produced and
//! keeps only the B-tree index entries in memory. When `finish` is called the
//! Node B-tree (NBT) and Block B-tree (BBT) pages are written, the allocation
//! map pages are filled in and finally the file header is written at offset 0.

use crate::crc::crc32;
use std::fs::File;
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::Path;

/// Maximum number of payload bytes in one block (8192 minus the trailer).
pub const MAX_BLOCK_DATA: usize = 8176;

const PAGE_SIZE: u64 = 512;
const HEADER_SIZE: usize = 564;
/// File offset of the first allocation map page.
const AMAP_START: u64 = 0x4400;
/// Number of bytes described by one AMap page (496 bytes * 8 bits * 64 bytes).
const AMAP_SPAN: u64 = 496 * 8 * 64;

const XBLOCK_MAX: usize = (MAX_BLOCK_DATA - 8) / 8; // 1021 BIDs per XBLOCK
const SL_MAX: usize = (MAX_BLOCK_DATA - 8) / 24; // 340 entries per SLBLOCK
const SI_MAX: usize = (MAX_BLOCK_DATA - 8) / 16; // 510 entries per SIBLOCK

const PTYPE_BBT: u8 = 0x80;
const PTYPE_NBT: u8 = 0x81;
const PTYPE_FMAP: u8 = 0x82;
const PTYPE_PMAP: u8 = 0x83;
const PTYPE_AMAP: u8 = 0x84;
const PTYPE_FPMAP: u8 = 0x85;

/// The content of a node: its data stream split into blocks, plus subnodes.
#[derive(Default)]
pub struct NodeContent {
    pub blocks: Vec<Vec<u8>>,
    pub subnodes: Vec<SubNode>,
}

pub struct SubNode {
    pub nid: u32,
    pub content: NodeContent,
}

impl NodeContent {
    /// Split a flat byte stream into maximum-size data blocks.
    pub fn from_stream(data: &[u8]) -> Self {
        let blocks: Vec<Vec<u8>> = data.chunks(MAX_BLOCK_DATA).map(|c| c.to_vec()).collect();
        NodeContent { blocks, subnodes: Vec::new() }
    }
}

struct BbtEntry {
    bid: u64,
    ib: u64,
    cb: u16,
}

struct NbtEntry {
    nid: u32,
    bid_data: u64,
    bid_sub: u64,
    parent: u32,
}

fn align_up(v: u64, a: u64) -> u64 {
    (v + a - 1) / a * a
}

/// Longest run of free (zero) 64-byte slots in an AMap, capped at 255:
/// the per-AMap value stored in FMap pages and in the header's rgbFM.
fn max_free_run(map: &[u8]) -> u8 {
    let (mut best, mut run) = (0u32, 0u32);
    for &byte in map {
        for bit in 0..8 {
            if byte & (0x80 >> bit) == 0 {
                run += 1;
                best = best.max(run);
            } else {
                run = 0;
            }
        }
    }
    best.min(255) as u8
}

/// [MS-PST] 5.5 ComputeSig.
fn compute_sig(ib: u64, bid: u64) -> u16 {
    let v = ib ^ bid;
    ((v >> 16) as u16) ^ (v as u16)
}

fn region_start(i: u64) -> u64 {
    AMAP_START + i * AMAP_SPAN
}

/// Page types that are reserved at the start of AMap region `i`, in order.
fn region_map_pages(i: u64) -> Vec<u8> {
    let mut v = vec![PTYPE_AMAP];
    if i % 8 == 0 {
        v.push(PTYPE_PMAP);
    }
    if i >= 128 && (i - 128) % 496 == 0 {
        v.push(PTYPE_FMAP);
    }
    if i >= 8192 && (i - 8192) % 31744 == 0 {
        // The FPMap lives in the fourth page slot; keep the FMap slot reserved.
        while v.len() < 3 {
            v.push(0);
        }
        v.push(PTYPE_FPMAP);
    }
    v
}

pub struct NdbWriter {
    out: BufWriter<File>,
    pos: u64,
    next_bid: u64,
    amaps: Vec<Vec<u8>>,
    bbt: Vec<BbtEntry>,
    nbt: Vec<NbtEntry>,
    /// Highest NID index used per NID type, including subnode NIDs.
    max_index: [u32; 32],
}

impl NdbWriter {
    pub fn create(path: &Path) -> io::Result<Self> {
        let file = File::create(path)?;
        let mut w = NdbWriter {
            out: BufWriter::with_capacity(1 << 20, file),
            pos: 0,
            next_bid: 4,
            amaps: Vec::new(),
            bbt: Vec::new(),
            nbt: Vec::new(),
            max_index: [0; 32],
        };
        // Header area (header + unused space up to the first AMap); the
        // real header is written last.
        w.pad_to(AMAP_START)?;
        Ok(w)
    }

    fn note_nid(&mut self, nid: u32) {
        let t = (nid & 0x1F) as usize;
        self.max_index[t] = self.max_index[t].max(nid >> 5);
    }

    fn new_bid(&mut self) -> u64 {
        let b = self.next_bid;
        self.next_bid += 4;
        b
    }

    fn pad_to(&mut self, target: u64) -> io::Result<()> {
        const ZEROS: [u8; 4096] = [0; 4096];
        while self.pos < target {
            let n = ((target - self.pos) as usize).min(ZEROS.len());
            self.out.write_all(&ZEROS[..n])?;
            self.pos += n as u64;
        }
        Ok(())
    }

    fn mark(&mut self, ib: u64, size: u64) {
        let idx = ((ib - AMAP_START) / AMAP_SPAN) as usize;
        let off = ib - region_start(idx as u64);
        let first = off / 64;
        let last = (off + size) / 64;
        let map = &mut self.amaps[idx];
        for unit in first..last {
            map[(unit / 8) as usize] |= 0x80 >> (unit % 8);
        }
    }

    /// Write placeholder pages for the map pages at the start of a new AMap region.
    fn init_region(&mut self) -> io::Result<()> {
        let i = self.amaps.len() as u64;
        let start = region_start(i);
        self.pad_to(start)?;
        self.amaps.push(vec![0u8; 496]);
        let n = region_map_pages(i).len() as u64;
        self.pad_to(start + n * PAGE_SIZE)?;
        self.mark(start, n * PAGE_SIZE);
        Ok(())
    }

    /// Reserve `size` bytes at the end of the file with the given alignment.
    /// The caller must immediately write exactly `size` bytes.
    fn alloc(&mut self, size: u64, align: u64) -> io::Result<u64> {
        loop {
            let p = align_up(self.pos, align);
            let idx = (p - AMAP_START) / AMAP_SPAN;
            if idx >= self.amaps.len() as u64 {
                self.init_region()?;
                continue;
            }
            let end_of_region = region_start(idx) + AMAP_SPAN;
            if p + size > end_of_region {
                self.pad_to(end_of_region)?;
                continue;
            }
            self.pad_to(p)?;
            self.pos = p + size;
            self.mark(p, size);
            return Ok(p);
        }
    }

    /// Write one block; returns its BID.
    pub fn write_block(&mut self, data: &[u8], internal: bool) -> io::Result<u64> {
        assert!(!data.is_empty() && data.len() <= MAX_BLOCK_DATA);
        let bid = self.new_bid() | if internal { 2 } else { 0 };
        let total = align_up(data.len() as u64 + 16, 64);
        let ib = self.alloc(total, 64)?;
        let mut buf = vec![0u8; total as usize];
        buf[..data.len()].copy_from_slice(data);
        let t = total as usize - 16;
        buf[t..t + 2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        buf[t + 2..t + 4].copy_from_slice(&compute_sig(ib, bid).to_le_bytes());
        buf[t + 4..t + 8].copy_from_slice(&crc32(data).to_le_bytes());
        buf[t + 8..t + 16].copy_from_slice(&bid.to_le_bytes());
        self.out.write_all(&buf)?;
        self.bbt.push(BbtEntry { bid, ib, cb: data.len() as u16 });
        Ok(bid)
    }

    /// Write a data tree (single block, XBLOCK or XXBLOCK); returns the root
    /// BID, or 0 for a node without data (Outlook never writes empty blocks).
    pub fn write_data_tree(&mut self, blocks: &[Vec<u8>]) -> io::Result<u64> {
        if blocks.iter().all(|b| b.is_empty()) {
            return Ok(0);
        }
        // Outlook (scanpst: "Middle page not full") requires every block of a
        // multi-block data tree except the last to hold exactly MAX_BLOCK_DATA bytes.
        if let Some((_, init)) = blocks.split_last() {
            if init.iter().any(|b| b.len() != MAX_BLOCK_DATA) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "internal error: data tree block not full"));
            }
        }
        if blocks.len() == 1 {
            return self.write_block(&blocks[0], false);
        }
        let mut leaves = Vec::with_capacity(blocks.len());
        for b in blocks {
            leaves.push((self.write_block(b, false)?, b.len() as u64));
        }
        let total: u64 = leaves.iter().map(|l| l.1).sum();
        if total > u32::MAX as u64 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "node data larger than 4 GiB"));
        }
        let mut xblocks = Vec::new();
        for chunk in leaves.chunks(XBLOCK_MAX) {
            let sub: u64 = chunk.iter().map(|l| l.1).sum();
            let mut x = Vec::with_capacity(8 + chunk.len() * 8);
            x.push(0x01); // btype
            x.push(0x01); // cLevel
            x.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            x.extend_from_slice(&(sub as u32).to_le_bytes());
            for (bid, _) in chunk {
                x.extend_from_slice(&bid.to_le_bytes());
            }
            xblocks.push(self.write_block(&x, true)?);
        }
        if xblocks.len() == 1 {
            return Ok(xblocks[0]);
        }
        if xblocks.len() > XBLOCK_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "node data too large"));
        }
        let mut xx = Vec::with_capacity(8 + xblocks.len() * 8);
        xx.push(0x01);
        xx.push(0x02);
        xx.extend_from_slice(&(xblocks.len() as u16).to_le_bytes());
        xx.extend_from_slice(&(total as u32).to_le_bytes());
        for bid in &xblocks {
            xx.extend_from_slice(&bid.to_le_bytes());
        }
        self.write_block(&xx, true)
    }

    /// Write a subnode B-tree (SLBLOCK / SIBLOCK); returns root BID or 0.
    pub fn write_subnodes(&mut self, subs: &[SubNode]) -> io::Result<u64> {
        if subs.is_empty() {
            return Ok(0);
        }
        let mut entries = Vec::with_capacity(subs.len());
        for s in subs {
            self.note_nid(s.nid);
            let bid_data = self.write_data_tree(&s.content.blocks)?;
            let bid_sub = self.write_subnodes(&s.content.subnodes)?;
            entries.push((s.nid, bid_data, bid_sub));
        }
        entries.sort_by_key(|e| e.0);
        let mut leaves = Vec::new();
        for chunk in entries.chunks(SL_MAX) {
            let mut b = Vec::with_capacity(8 + chunk.len() * 24);
            b.push(0x02); // btype
            b.push(0x00); // cLevel
            b.extend_from_slice(&(chunk.len() as u16).to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            for (nid, d, s) in chunk {
                b.extend_from_slice(&(*nid as u64).to_le_bytes());
                b.extend_from_slice(&d.to_le_bytes());
                b.extend_from_slice(&s.to_le_bytes());
            }
            leaves.push((chunk[0].0, self.write_block(&b, true)?));
        }
        if leaves.len() == 1 {
            return Ok(leaves[0].1);
        }
        if leaves.len() > SI_MAX {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many subnodes"));
        }
        let mut b = Vec::with_capacity(8 + leaves.len() * 16);
        b.push(0x02);
        b.push(0x01);
        b.extend_from_slice(&(leaves.len() as u16).to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
        for (nid, bid) in &leaves {
            b.extend_from_slice(&(*nid as u64).to_le_bytes());
            b.extend_from_slice(&bid.to_le_bytes());
        }
        self.write_block(&b, true)
    }

    /// Write a complete node and register it in the NBT.
    pub fn add_node(&mut self, nid: u32, parent: u32, content: &NodeContent) -> io::Result<()> {
        self.note_nid(nid);
        let bid_data = self.write_data_tree(&content.blocks)?;
        let bid_sub = self.write_subnodes(&content.subnodes)?;
        self.nbt.push(NbtEntry { nid, bid_data, bid_sub, parent });
        Ok(())
    }

    /// Register a node that has no data at all (bidData = 0), as Outlook
    /// does for empty search queues.
    pub fn add_empty_node(&mut self, nid: u32, parent: u32) {
        self.note_nid(nid);
        self.nbt.push(NbtEntry { nid, bid_data: 0, bid_sub: 0, parent });
    }

    /// Write a 512-byte B-tree page; `body` holds the first 496 bytes.
    fn write_page(&mut self, body: &[u8], ptype: u8) -> io::Result<(u64, u64)> {
        let bid = self.new_bid();
        let ib = self.alloc(PAGE_SIZE, PAGE_SIZE)?;
        let mut page = [0u8; 512];
        page[..496].copy_from_slice(&body[..496]);
        page[496] = ptype;
        page[497] = ptype;
        page[498..500].copy_from_slice(&compute_sig(ib, bid).to_le_bytes());
        let crc = crc32(&page[..496]);
        page[500..504].copy_from_slice(&crc.to_le_bytes());
        page[504..512].copy_from_slice(&bid.to_le_bytes());
        self.out.write_all(&page)?;
        Ok((bid, ib))
    }

    /// Build a B-tree bottom-up from sorted (key, leaf entry) pairs.
    /// Returns the BREF (bid, ib) of the root page.
    fn write_btree(&mut self, entries: &[(u64, Vec<u8>)], ptype: u8, cb_leaf: usize) -> io::Result<(u64, u64)> {
        let mut level: u8 = 0;
        let mut nodes: Vec<(u64, u64, u64)> = Vec::new(); // (first key, bid, ib)
        let max_leaf = 488 / cb_leaf;
        let empty: [(u64, Vec<u8>); 0] = [];
        let chunks: Vec<&[(u64, Vec<u8>)]> =
            if entries.is_empty() { vec![&empty[..]] } else { entries.chunks(max_leaf).collect() };
        for chunk in chunks {
            let mut body = [0u8; 496];
            for (i, (_, e)) in chunk.iter().enumerate() {
                body[i * cb_leaf..(i + 1) * cb_leaf].copy_from_slice(e);
            }
            body[488] = chunk.len() as u8;
            body[489] = max_leaf as u8;
            body[490] = cb_leaf as u8;
            body[491] = 0;
            let (bid, ib) = self.write_page(&body, ptype)?;
            nodes.push((chunk.first().map(|c| c.0).unwrap_or(0), bid, ib));
        }
        while nodes.len() > 1 {
            level += 1;
            let mut next = Vec::new();
            for chunk in nodes.chunks(20) {
                let mut body = [0u8; 496];
                for (i, (key, bid, ib)) in chunk.iter().enumerate() {
                    let o = i * 24;
                    body[o..o + 8].copy_from_slice(&key.to_le_bytes());
                    body[o + 8..o + 16].copy_from_slice(&bid.to_le_bytes());
                    body[o + 16..o + 24].copy_from_slice(&ib.to_le_bytes());
                }
                body[488] = chunk.len() as u8;
                body[489] = 20;
                body[490] = 24;
                body[491] = level;
                let (bid, ib) = self.write_page(&body, ptype)?;
                next.push((chunk[0].0, bid, ib));
            }
            nodes = next;
        }
        Ok((nodes[0].1, nodes[0].2))
    }

    /// Write the B-trees, allocation maps and header, then close the file.
    pub fn finish(mut self) -> io::Result<u64> {
        // Node B-tree.
        self.nbt.sort_by_key(|e| e.nid);
        for w in self.nbt.windows(2) {
            if w[0].nid == w[1].nid {
                return Err(io::Error::new(io::ErrorKind::InvalidData, format!("duplicate NID {:#x}", w[0].nid)));
            }
        }
        let nbt_entries: Vec<(u64, Vec<u8>)> = self
            .nbt
            .iter()
            .map(|e| {
                let mut v = Vec::with_capacity(32);
                v.extend_from_slice(&(e.nid as u64).to_le_bytes());
                v.extend_from_slice(&e.bid_data.to_le_bytes());
                v.extend_from_slice(&e.bid_sub.to_le_bytes());
                v.extend_from_slice(&e.parent.to_le_bytes());
                v.extend_from_slice(&0u32.to_le_bytes());
                (e.nid as u64, v)
            })
            .collect();

        // Block B-tree (BIDs are allocated in increasing order already).
        self.bbt.sort_by_key(|e| e.bid);
        let bbt_entries: Vec<(u64, Vec<u8>)> = self
            .bbt
            .iter()
            .map(|e| {
                let mut v = Vec::with_capacity(24);
                v.extend_from_slice(&e.bid.to_le_bytes());
                v.extend_from_slice(&e.ib.to_le_bytes());
                v.extend_from_slice(&e.cb.to_le_bytes());
                v.extend_from_slice(&2u16.to_le_bytes()); // cRef
                v.extend_from_slice(&0u32.to_le_bytes());
                (e.bid, v)
            })
            .collect();

        let nbt_root = self.write_btree(&nbt_entries, PTYPE_NBT, 32)?;
        let bbt_root = self.write_btree(&bbt_entries, PTYPE_BBT, 24)?;

        // Extend the file to cover the last AMap region completely, as Outlook does.
        let last = self.amaps.len() as u64 - 1;
        let eof = region_start(last) + AMAP_SPAN;
        self.pad_to(eof)?;

        // Allocation maps and the deprecated PMap/FMap/FPMap pages.
        let fmap: Vec<u8> = self.amaps.iter().map(|m| max_free_run(m)).collect();
        let mut free_bytes: u64 = 0;
        for i in 0..self.amaps.len() {
            let start = region_start(i as u64);
            let map = self.amaps[i].clone();
            free_bytes += map.iter().map(|b| b.count_zeros() as u64).sum::<u64>() * 64;
            for (k, ptype) in region_map_pages(i as u64).into_iter().enumerate() {
                let ib = start + k as u64 * PAGE_SIZE;
                let mut page = [0u8; 512];
                match ptype {
                    PTYPE_AMAP => page[..496].copy_from_slice(&map),
                    PTYPE_PMAP | PTYPE_FPMAP => page[..496].fill(0xFF),
                    PTYPE_FMAP => {
                        // One byte per AMap, starting with the AMap that holds this FMap.
                        for (k, b) in page[..496].iter_mut().enumerate() {
                            *b = fmap.get(i + k).copied().unwrap_or(0);
                        }
                    }
                    _ => continue, // unused reserved slot
                }
                page[496] = ptype;
                page[497] = ptype;
                // wSig is 0 for map pages; the BID is the page's file offset.
                let crc = crc32(&page[..496]);
        page[500..504].copy_from_slice(&crc.to_le_bytes());
                page[504..512].copy_from_slice(&ib.to_le_bytes());
                self.out.seek(SeekFrom::Start(ib))?;
                self.out.write_all(&page)?;
            }
        }

        // NID high-water marks (rgnid): Outlook stores the last-used nidIndex
        // per NID type, and related types share one counter: a folder and its
        // hierarchy/contents/associated-contents tables use the same index, as
        // do a search folder and its tables. scanpst reports
        // "invalid high-water-mark" if a group disagrees or lags behind.
        let mut rgnid = [0x400u32; 32];
        for t in 0..32 {
            rgnid[t] = rgnid[t].max(self.max_index[t]);
        }
        for group in [&[0x02usize, 0x0D, 0x0E, 0x0F][..], &[0x03, 0x06, 0x07, 0x10][..]] {
            let m = group.iter().map(|&t| rgnid[t]).max().unwrap();
            for &t in group {
                rgnid[t] = m;
            }
        }

        let mut h = [0u8; HEADER_SIZE];
        h[0..4].copy_from_slice(b"!BDN");
        h[8..10].copy_from_slice(b"SM");
        h[10..12].copy_from_slice(&23u16.to_le_bytes()); // wVer: Unicode
        h[12..14].copy_from_slice(&19u16.to_le_bytes()); // wVerClient
        h[14] = 0x01; // bPlatformCreate
        h[15] = 0x01; // bPlatformAccess
        h[32..40].copy_from_slice(&self.next_bid.to_le_bytes()); // bidNextP
        h[40..44].copy_from_slice(&1u32.to_le_bytes()); // dwUnique
        for (i, n) in rgnid.iter().enumerate() {
            h[44 + i * 4..48 + i * 4].copy_from_slice(&n.to_le_bytes());
        }
        // ROOT at offset 180
        let r = 180;
        h[r + 4..r + 12].copy_from_slice(&eof.to_le_bytes()); // ibFileEof
        h[r + 12..r + 20].copy_from_slice(&region_start(last).to_le_bytes()); // ibAMapLast
        h[r + 20..r + 28].copy_from_slice(&free_bytes.to_le_bytes()); // cbAMapFree
        h[r + 28..r + 36].copy_from_slice(&0u64.to_le_bytes()); // cbPMapFree
        h[r + 36..r + 44].copy_from_slice(&nbt_root.0.to_le_bytes());
        h[r + 44..r + 52].copy_from_slice(&nbt_root.1.to_le_bytes());
        h[r + 52..r + 60].copy_from_slice(&bbt_root.0.to_le_bytes());
        h[r + 60..r + 68].copy_from_slice(&bbt_root.1.to_le_bytes());
        h[r + 68] = 0x02; // fAMapValid = VALID_AMAP2
        // rgbFM: longest free run for each of the first 128 AMaps (as Outlook's
        // AMap rebuild writes it), 0 for AMaps that do not exist.
        for (k, b) in h[256..384].iter_mut().enumerate() {
            *b = fmap.get(k).copied().unwrap_or(0);
        }
        h[384..512].fill(0xFF); // rgbFP (deprecated)
        h[512] = 0x80; // bSentinel
        h[513] = 0x00; // bCryptMethod = NDB_CRYPT_NONE
        h[516..524].copy_from_slice(&self.next_bid.to_le_bytes()); // bidNextB
        let partial = crc32(&h[8..8 + 471]);
        h[4..8].copy_from_slice(&partial.to_le_bytes());
        let full = crc32(&h[8..8 + 516]);
        h[524..528].copy_from_slice(&full.to_le_bytes());

        self.out.seek(SeekFrom::Start(0))?;
        self.out.write_all(&h)?;
        self.out.flush()?;
        self.out.get_ref().sync_all()?;
        Ok(eof)
    }
}
