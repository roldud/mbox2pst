#!/usr/bin/env python3
"""Structural and logical validator for Unicode PST files (written from [MS-PST]).

Works on files written by mbox2pst and on files created or modified by
Outlook (including Outlook's "compressible" and "high" encryption).

Physical checks: header CRCs; every NBT/BBT page (type, signature, CRC, BID,
key order); every block trailer (size, signature, CRC, BID); data trees
(XBLOCK/XXBLOCK) and subnode trees (SLBLOCK/SIBLOCK); allocation maps (every
page/block marked, no overlaps, free-space total).

LTP checks: heap-on-node page maps; BTH structure; every property and table
cell that refers to the heap or to a subnode resolves.

Outlook / scanpst rules (not all are in the published specification; they
were established from scanpst.exe reports and Outlook-created files):
blocks hold 1..8176 bytes and every block of a multi-block data tree except
the last is full; BTH keys are non-zero; NID high-water marks (rgnid) cover
every NID in use, with related NID types sharing one counter; FMap entries
equal the longest free run of their AMap; tables carry all columns of
Outlook's templates; table rows match the objects they describe (folders,
messages, attachments); PR_ATTACH_SIZE equals the total size of the
attachment's properties; messages have PR_SEARCH_KEY; folders have
PR_DISPLAY_NAME; the receive-folder table has a default entry; each normal
folder has its three tables; hierarchy rows match child folders and their
node-tree parents; folder counts are consistent.

Findings that violate the specification are reported as ERROR. Legal but
notable conditions (for example structures Outlook adds for its own use) are
reported as NOTE. The exit status is 1 if there is any ERROR.

Usage: validate_pst.py FILE.pst [--quiet]
"""
import struct, sys, zlib
from collections import Counter

# Byte-substitution tables of [MS-PST] 5.1 (mpbbCrypt): decode table for
# NDB_CRYPT_PERMUTE, and the two extra tables used by NDB_CRYPT_CYCLIC.
TABLES = {'compressible': '47f1b4e60b6a7248854e9eebe2f89453e0bba002e85a09abdbe3bac67cc310dd39059630f53760828cc9134a6b1df3fb8f2697ca911701c4322d6e3195ffd923d1005e79dc443b1a28c5615720903d83b943be67d2464276c06d5b7eb20f16293ca903540dda5ddff6b7c762cd8d06d3695c86d614f7a56675acb1e94521700c879f74a4224c6fbf1f56aa2eb3783350b0a392bccf191ca763cb1e4d3e4b1b9b4fe7f0eead3ab55904ea40552551e57a893868527bfc27aed7bdfa07f4cc8e5fef359c842b15d5773449b6120a7f7188fd9d18417d93d8582ccefe24afdeb836c8a180a69998a82f0e816573e4c2a28ad4e111d0088b2af2ed9a643fc16cf9ec', 'high1': '41361362a8216ebbf416cc047f64e85d1ef2cb2a74c55e35d295479e962d9a884c7d843fdbac31b6485ff6c4d8398be7233b388ec8c1df25b120a546604e9cfbaad35651457c550007c92b9d859b09a08fadb30f63ab894bd7a7155a716642bf264a6b98faea7753b270052cfd593a867ece06eb827857c78d43afb41cd45bcde2e9274fc3087280cfb0eff5286dbe304d3492d50e3c2232e5e4f99fc2d10a8112e1ee918376e397e6618a1779a4b7dc907a5c8c02a6ca69de501a1193b9528758fced1d37491b6ae0293399bd6cd994f340546ff0c673b8d63e6518441fdd6710f10c19ecae03a1147ba90bfff8a3c0a201f72ebc2468750dfeba2fb5d0da3d', 'high2': '14530f56b3c87a9ceb65481716159f02cc547c83000d0c0ba262a876dbd9edc7c5a4dcac8574d6d0a79bae9a967166c36399b8dd73928e847da55ed15d93b1575150808952944f4e0a6bbc8d7f6e47464140440111cb033ff7f4e1a98f3c3af9fbf0193082092ec99da08649ee6f4d6dc42d813425871b88aafc06a11238fd4c4272641337246a757743ffe6b44b365ce4d8353d45b92cecb7312b290768a30e697b189e2139be281a5b78f523ca2ab0af3efe048ce7e5983295d3f64ae8a6eae9f3d52f7020f21f0567ad5510cecde3273bdabad7c226d4911dd21c2233f8faf15aefcf90b68bb5bdc0bf08971e6ce261e0c6c159abbb58de5fdf60797eb28a'}
DEC = bytes.fromhex(TABLES['compressible'])
H1 = bytes.fromhex(TABLES['high1'])
H2 = bytes.fromhex(TABLES['high2'])
TRANS = bytes.maketrans(bytes(range(256)), DEC)


def crc(b):  # PST CRC: reflected CRC-32 with initial value 0 and no final XOR
    return zlib.crc32(b, 0xFFFFFFFF) ^ 0xFFFFFFFF


def sig(ib, bid):
    v = ib ^ bid
    return ((v >> 16) ^ v) & 0xFFFF


errors, notes = [], Counter()
QUIET = '--quiet' in sys.argv


def err(msg):
    errors.append(msg)
    if not QUIET and len(errors) <= 40:
        print('ERROR:', msg)


def note(kind):
    notes[kind] += 1


args = [a for a in sys.argv[1:] if not a.startswith('--')]
if len(args) != 1:
    sys.exit(__doc__)
data = open(args[0], 'rb').read()

# ------------------------------------------------------------------ header
if len(data) < 564 or data[0:4] != b'!BDN' or data[8:10] not in (b'SM', b'SO'):
    sys.exit('Not a PST/OST file (bad magic).')
wver = struct.unpack_from('<H', data, 10)[0]
if wver in (14, 15):
    sys.exit('ANSI (Outlook 97-2002) PST: not supported by this validator.')
if wver >= 36:
    sys.exit(f'4K-page format (wVer {wver}, Outlook 2013+ OST): not supported by this validator.')
if wver not in (21, 23):
    sys.exit(f'Unknown PST version {wver}.')
H = data[:564]
if struct.unpack_from('<I', H, 4)[0] != crc(H[8:8 + 471]):
    err('header partial CRC')
if struct.unpack_from('<I', H, 524)[0] != crc(H[8:8 + 516]):
    err('header full CRC')
R = 180
eof, amap_last, amap_free, pmap_free = struct.unpack_from('<QQQQ', H, R + 4)
nbt_bid, nbt_ib, bbt_bid, bbt_ib = struct.unpack_from('<QQQQ', H, R + 36)
amap_valid = H[R + 68]
crypt = H[513]
bid_next_b = struct.unpack_from('<Q', H, 516)[0]
bid_next_p = struct.unpack_from('<Q', H, 32)[0]
if eof != len(data):
    err(f'ibFileEof {eof} != file size {len(data)}')
if crypt not in (0, 1, 2):
    err(f'unknown bCryptMethod {crypt}')
CRYPT_NAMES = {0: 'none', 1: 'compressible (permute)', 2: 'high (cyclic)'}


def decode(b, bid):
    if crypt == 1:
        return b.translate(TRANS)
    if crypt == 2:
        key = bid & 0xFFFFFFFF
        salt = ((key >> 16) ^ key) & 0xFFFF
        out = bytearray(b)
        for i, x in enumerate(out):
            lo, hi = salt & 0xFF, salt >> 8
            v = H1[(x + lo) & 0xFF]
            v = H2[(v + hi) & 0xFF]
            v = DEC[(v - hi) & 0xFF]
            out[i] = (v - lo) & 0xFF
            salt = (salt + 1) & 0xFFFF
        return bytes(out)
    return b


# ------------------------------------------------------------------ B-trees
allocated = []  # (ib, size, what)


def read_page(ib, bid, ptype):
    if ib % 512 or ib + 512 > len(data):
        err(f'page @{ib:#x} misaligned or beyond end of file')
        return bytes(512)
    p = data[ib:ib + 512]
    allocated.append((ib, 512, f'page {ptype:#x}'))
    if p[496] != ptype or p[497] != ptype:
        err(f'page @{ib:#x}: type {p[496]:#x}, expected {ptype:#x}')
    w, c, b = struct.unpack_from('<HIQ', p, 498)
    if c != crc(p[:496]):
        err(f'page @{ib:#x}: CRC')
    if b != bid:
        err(f'page @{ib:#x}: BID {b:#x} != {bid:#x}')
    if w != sig(ib, bid):
        err(f'page @{ib:#x}: signature')
    if bid >= bid_next_p:
        err(f'page BID {bid:#x} >= bidNextP')
    return p


def walk_bt(bid, ib, ptype, leaf_size, out, depth=0):
    p = read_page(ib, bid, ptype)
    cent, cmax, cb, lvl = p[488], p[489], p[490], p[491]
    if cent > cmax or cb * cmax > 488:
        err(f'page @{ib:#x}: bad cEnt/cEntMax/cbEnt')
        return None
    keys = []
    if lvl == 0:
        if cb < leaf_size:
            err(f'page @{ib:#x}: leaf cbEnt {cb}')
            return None
        for i in range(cent):
            e = p[i * cb:i * cb + leaf_size]
            out.append(e)
            k = struct.unpack_from('<Q', e)[0]
            keys.append(k & 0xFFFFFFFF if ptype == 0x81 else k)
    else:
        if cb < 24 or depth > 16:
            err(f'page @{ib:#x}: bad index page')
            return None
        for i in range(cent):
            k, cbid, cib = struct.unpack_from('<QQQ', p, i * cb)
            keys.append(k)
            first = walk_bt(cbid, cib, ptype, leaf_size, out, depth + 1)
            if first is not None and first != k:
                err(f'BTENTRY key {k:#x} != first key of child page {first:#x}')
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        err(f'page @{ib:#x}: keys not strictly sorted')
    return keys[0] if keys else None


bbt_raw, nbt_raw = [], []
walk_bt(bbt_bid, bbt_ib, 0x80, 24, bbt_raw)
walk_bt(nbt_bid, nbt_ib, 0x81, 32, nbt_raw)

bbt = {}
for e in bbt_raw:
    bid, ib, cb, cref = struct.unpack_from('<QQHH', e)
    total = (cb + 16 + 63) // 64 * 64
    if bid & ~1 in bbt:
        err(f'duplicate BBT entry {bid:#x}')
    bbt[bid & ~1] = (ib, cb)
    if ib % 64 or ib + total > len(data):
        err(f'block {bid:#x} misaligned or beyond end of file')
        continue
    allocated.append((ib, total, f'block {bid:#x}'))
    blk = data[ib:ib + total]
    tcb, tsig, tcrc, tbid = struct.unpack_from('<HHIQ', blk, total - 16)
    if tcb != cb:
        err(f'block {bid:#x}: trailer size {tcb} != BBT size {cb}')
    if tbid != bid:
        err(f'block {bid:#x}: trailer BID {tbid:#x}')
    if tsig != sig(ib, bid):
        err(f'block {bid:#x}: signature')
    if tcrc != crc(blk[:cb]):
        err(f'block {bid:#x}: CRC')
    if bid >= bid_next_b:
        err(f'block BID {bid:#x} >= bidNextB')
used = set()


def block(bid):
    bid &= ~1
    if bid not in bbt:
        err(f'reference to missing block {bid:#x}')
        return b''
    used.add(bid)
    ib, cb = bbt[bid]
    raw = data[ib:ib + cb]
    return raw if bid & 2 else decode(raw, bid)  # internal blocks are never encrypted


def data_tree(bid, outer=True):
    """Leaf data blocks of a node; an empty list for a node without data (bidData 0)."""
    if bid == 0:
        note('nodes without data (bidData = 0)')
        return []
    b = block(bid)
    if not bid & 2:
        if not b:
            err(f'data block {bid:#x} is empty (Outlook requires 1..8176 bytes; use bidData 0 for no data)')
        return [b]
    if len(b) < 8 or b[0] != 1 or b[1] not in (1, 2):
        err(f'bad XBLOCK/XXBLOCK {bid:#x}')
        return []
    lvl, cent, total = b[1], *struct.unpack_from('<HI', b, 2)
    out = []
    for i in range(cent):
        child = struct.unpack_from('<Q', b, 8 + i * 8)[0]
        if lvl == 1:
            if child & 2:
                err(f'XBLOCK {bid:#x} points to an internal block')
            out.append(block(child))
        else:
            out.extend(data_tree(child, False))
    if sum(len(x) for x in out) != total:
        err(f'XBLOCK {bid:#x}: lcbTotal mismatch')
    short = [i for i, x in enumerate(out[:-1]) if len(x) != 8176]
    if outer and short:
        err(f'data tree {bid:#x}: block {short[0]} of {len(out)} holds {len(out[short[0]])} bytes; '
                f'all but the last must be full (scanpst: "Middle page not full")')
    return out


def subnodes(bid, depth=0):
    res = {}
    if bid == 0:
        return res
    b = block(bid)
    if len(b) < 8 or b[0] != 2 or depth > 8:
        err(f'bad SLBLOCK/SIBLOCK {bid:#x}')
        return res
    lvl, cent = b[1], struct.unpack_from('<H', b, 2)[0]
    keys = []
    for i in range(cent):
        # The 8-byte nid field holds a 4-byte NID; Outlook may leave
        # uninitialised bytes in the upper half, so only the low 32 bits count.
        if lvl == 0:
            nid, d, s = struct.unpack_from('<QQQ', b, 8 + i * 24)
            nid &= 0xFFFFFFFF
            if nid in res:
                err(f'subnode block {bid:#x}: duplicate subnode {nid:#x}')
            res[nid] = (d, s)
            keys.append(nid)
        else:
            nid, child = struct.unpack_from('<QQ', b, 8 + i * 16)
            nid &= 0xFFFFFFFF
            sub = subnodes(child, depth + 1)
            keys.append(nid)
            if sub and min(sub) != nid:
                err(f'SIBLOCK {bid:#x}: key does not match child')
            res.update(sub)
    if keys != sorted(keys):
        err(f'subnode block {bid:#x}: keys unsorted')
    return res


# ------------------------------------------------------------------ LTP
class Heap:
    def __init__(self, blocks, what):
        self.pages, self.what = [], what
        for i, b in enumerate(blocks):
            page = []
            self.pages.append(page)
            if len(b) < 2:
                err(f'{what}: heap block {i} too short')
                continue
            ibh = struct.unpack_from('<H', b, 0)[0]
            if ibh + 4 > len(b):
                err(f'{what}: heap block {i}: bad ibHnpm')
                continue
            calloc, cfree = struct.unpack_from('<HH', b, ibh)
            if ibh + 4 + 2 * (calloc + 1) > len(b):
                err(f'{what}: heap block {i}: page map overruns block')
                continue
            offs = struct.unpack_from(f'<{calloc + 1}H', b, ibh + 4)
            hdr = 12 if i == 0 else (66 if i >= 8 and (i - 8) % 128 == 0 else 2)
            if offs[0] < hdr:
                err(f'{what}: heap block {i}: allocation overlaps header')
            if list(offs) != sorted(offs) or offs[-1] > ibh:
                err(f'{what}: heap block {i}: bad page map')
            page.extend(b[offs[k]:offs[k + 1]] for k in range(calloc))
        self.client = blocks[0][3]
        self.root = struct.unpack_from('<I', blocks[0], 4)[0]

    def get(self, hid):
        if hid & 0x1F:
            err(f'{self.what}: {hid:#x} is not a HID')
            return b''
        blk, idx = hid >> 16, (hid >> 5) & 0x7FF
        if blk < len(self.pages) and 1 <= idx <= len(self.pages[blk]):
            return self.pages[blk][idx - 1]
        err(f'{self.what}: HID {hid:#x} does not resolve')
        return b''


def bth(heap, hid):
    h = heap.get(hid)
    if len(h) < 8 or h[0] != 0xB5:
        err(f'{heap.what}: bad BTH header')
        return [], 0, 0
    ck, ce, lv, root = h[1], h[2], h[3], struct.unpack_from('<I', h, 4)[0]
    out = []

    def rec(hid, lvl):
        d = heap.get(hid)
        n = ck + (ce if lvl == 0 else 4)
        if n == 0 or len(d) % n:
            err(f'{heap.what}: BTH node size {len(d)} is not a multiple of {n}')
            return
        for i in range(len(d) // n):
            k = d[i * n:i * n + ck]
            if lvl == 0:
                out.append((int.from_bytes(k, 'little'), d[i * n + ck:i * n + n]))
            elif lvl < 8:
                rec(struct.unpack_from('<I', d, i * n + ck)[0], lvl - 1)

    if root:
        rec(root, lv)
    ks = [k for k, _ in out]
    if ks != sorted(ks) or len(set(ks)) != len(ks):
        err(f'{heap.what}: BTH keys not strictly sorted')
    if ks and ks[0] == 0:
        err(f'{heap.what}: BTH key 0 (scanpst: "keys overlap (dwkey=0)"; keys must be non-zero)')
    return out, ck, ce


def resolve(heap, subs, v, what):
    """Resolve an HNID: 0 (empty), a HID into the heap, or a subnode NID."""
    if v == 0:
        return b''
    if v & 0x1F == 0:
        return heap.get(v)
    if v not in subs:
        err(f'{what}: subnode {v:#x} missing')
        return b''
    return b''.join(data_tree(subs[v][0]))


FIXED_IN_PC = {0x0002, 0x0003, 0x0004, 0x000A, 0x000B}  # value stored inline in a PC record
ROW_FIXED = {0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x000A, 0x000B, 0x0014, 0x0040}  # inline in a TC row
RESERVED_CLIENTS = {0x6C, 0x8C, 0x9C, 0xA5, 0xAC, 0xCC}
stats = Counter()
COLS = {}
PCS, TCS = {}, {}   # keyed by path tuple: (nid,) for top-level nodes, (msg, sub) for subnodes
MAX_INDEX = Counter()


def check_node(nid, bid_data, bid_sub, what, path):
    blocks = data_tree(bid_data)
    subs = subnodes(bid_sub)
    if blocks and len(blocks[0]) >= 12 and blocks[0][2] == 0xEC:
        heap = Heap(blocks, what)
        if heap.client == 0xBC:
            stats['property_contexts'] += 1
            props = {}
            recs, ck, ce = bth(heap, heap.root)
            if recs and (ck, ce) != (2, 6):
                err(f'{what}: property context BTH has cbKey {ck}, cbEnt {ce}')
            for k, d in recs:
                pt, v = struct.unpack('<HI', d[:6])
                stats['properties'] += 1
                props[k] = (pt, v if pt in FIXED_IN_PC else resolve(heap, subs, v, f'{what} property {k:#06x}'))
            PCS[path] = props
        elif heap.client == 0x7C:
            stats['table_contexts'] += 1
            info = heap.get(heap.root)
            if len(info) < 22 or info[0] != 0x7C:
                err(f'{what}: bad TCINFO')
                return
            ccols = info[1]
            rgib = struct.unpack_from('<4H', info, 2)
            hidri, hnrows = struct.unpack_from('<II', info, 10)
            cols = [struct.unpack_from('<IHBB', info, 22 + 8 * i) for i in range(ccols)]
            rowsize = rgib[3]
            idx = bth(heap, hidri)[0] if hidri else []
            if hnrows == 0:
                rowsdata = b''
            elif hnrows & 0x1F == 0:
                rowsdata = heap.get(hnrows)
            elif hnrows in subs:
                per = 8176 // rowsize if rowsize else 1
                rowsdata = b''.join(b[:per * rowsize] for b in data_tree(subs[hnrows][0]))
            else:
                err(f'{what}: row matrix subnode {hnrows:#x} missing')
                rowsdata = b''
            nrows = len(rowsdata) // rowsize if rowsize else 0
            if len(idx) > nrows:
                err(f'{what}: row index has {len(idx)} rows, row matrix only {nrows}')
            stats['table_rows'] += len(idx)
            table = {}
            table_cols = {c[0] for c in cols}
            TCS[path] = table
            COLS[path] = table_cols
            for rid, d in idx:
                ri = int.from_bytes(d[:4], 'little')
                row = rowsdata[ri * rowsize:(ri + 1) * rowsize]
                if len(row) < rowsize:
                    err(f'{what}: row index {ri} out of range')
                    continue
                if struct.unpack_from('<I', row)[0] != rid:
                    err(f'{what}: row {ri} id does not match the row index')
                cells = table.setdefault(rid, {})
                for tag, ib, cb, ibit in cols:
                    if not row[rgib[2] + ibit // 8] & (0x80 >> (ibit % 8)):
                        continue
                    if (tag & 0xFFFF) not in ROW_FIXED and cb == 4:
                        cells[tag] = resolve(heap, subs, struct.unpack_from('<I', row, ib)[0], f'{what} column {tag:#010x}')
                    else:
                        cells[tag] = row[ib:ib + cb]
        elif heap.client == 0xB5:
            stats['standalone_bths'] += 1
            bth(heap, heap.root)
        elif heap.client in RESERVED_CLIENTS:
            note(f'heaps of Outlook-internal type {heap.client:#04x} (structure checked, content not interpreted)')
        else:
            err(f'{what}: unknown heap client signature {heap.client:#x}')
    for snid, (d, s) in subs.items():
        MAX_INDEX[snid & 0x1F] = max(MAX_INDEX[snid & 0x1F], snid >> 5)
        if snid & 0x1F in (0x04, 0x05, 0x11, 0x12):  # embedded messages, attachments, attachment/recipient tables
            check_node(snid, d, s, f'{what}/sub {snid:#x}', path + (snid,))


nbt = {}
for e in nbt_raw:
    nid, d, s, parent = struct.unpack_from('<QQQI', e)
    nbt[nid & 0xFFFFFFFF] = (d, s, parent)
for nid, (d, s, parent) in nbt.items():
    if parent and parent not in nbt:
        err(f'node {nid:#x}: parent {parent:#x} missing')
    MAX_INDEX[nid & 0x1F] = max(MAX_INDEX[nid & 0x1F], nid >> 5)
    try:
        check_node(nid, d, s, f'node {nid:#x}', (nid,))
    except Exception as ex:  # never let one malformed node stop the run
        err(f'node {nid:#x}: unreadable ({type(ex).__name__}: {ex})')

# ------------------------------------------------------------------ logical checks


def s16(b):
    return b.decode('utf-16-le', 'replace')


def i32(b):
    return struct.unpack('<i', b[:4])[0] if len(b) >= 4 else None


PCS_TOP = {k[0]: v for k, v in PCS.items() if len(k) == 1}
TCS_TOP = {k[0]: v for k, v in TCS.items() if len(k) == 1}

for need in (0x21, 0x61, 0x122):
    if need not in nbt:
        err(f'mandatory node {need:#x} missing')
NORMAL, SEARCH = 0x02, 0x03
folders = [n for n in nbt if n & 0x1F in (NORMAL, SEARCH)]
for f in folders:
    if f & 0x1F == SEARCH:
        stats['search_folders'] += 1  # contents come from a search; no hierarchy/contents tables of their own
        continue
    stats['folders'] += 1
    for t in (0xD, 0xE, 0xF):
        if (f & ~0x1F) | t not in TCS_TOP:
            err(f'folder {f:#x}: table of type {t:#x} missing')
    pc = PCS_TOP.get(f, {})
    kids = sorted(n for n in folders if nbt[n][2] == f and n != f)
    msgs = [n for n in nbt if n & 0x1F == 0x04 and nbt[n][2] == f]
    stats['messages'] += len(msgs)
    hier = TCS_TOP.get((f & ~0x1F) | 0xD, {})
    cont = TCS_TOP.get((f & ~0x1F) | 0xE, {})
    if sorted(hier) != kids:
        err(f'folder {f:#x}: hierarchy rows {sorted(map(hex, hier))} != child folders {list(map(hex, kids))}')
    if sorted(cont) != sorted(msgs):
        err(f'folder {f:#x}: {len(cont)} contents rows but {len(msgs)} messages')
    count = pc.get(0x3602, (0, None))[1]
    if count is not None and count != len(msgs):
        err(f'folder {f:#x}: PidTagContentCount {count} != {len(msgs)} messages')
    sub = pc.get(0x360A, (0, None))[1]
    if sub is not None and bool(sub) != bool(kids):
        err(f'folder {f:#x}: PidTagSubfolders is {bool(sub)} but folder has {len(kids)} subfolders')
    unread = sum(1 for m in msgs if not PCS_TOP.get(m, {}).get(0x0E07, (0, 1))[1] & 1)
    u = pc.get(0x3603, (0, None))[1]
    if u is not None and u != unread:
        err(f'folder {f:#x}: PidTagContentUnreadCount {u} != {unread}')
    names = []
    for k in kids:
        row, kpc = hier.get(k, {}), PCS_TOP.get(k, {})
        name = s16(kpc.get(0x3001, (0, b''))[1])
        names.append(name.strip().lower())
        if 0x3001001F in row and s16(row[0x3001001F]) != name:
            err(f'folder {k:#x}: hierarchy row name differs from folder name {name!r}')
        if 0x36020003 in row and i32(row[0x36020003]) != kpc.get(0x3602, (0, None))[1]:
            err(f'folder {k:#x}: hierarchy row message count differs from folder')
        if k & 0x1F == NORMAL and not name.strip():
            note('folders with an empty name')
        elif name != name.strip():
            note('folder names with leading/trailing whitespace')
    if len(set(names)) != len(names):
        note('sibling folders with the same name')
    for m in msgs:
        row, mpc = cont.get(m, {}), PCS_TOP.get(m, {})
        for pid, tag in ((0x0037, 0x0037001F), (0x0E07, 0x0E070003), (0x001A, 0x001A001F)):
            pv, rv = mpc.get(pid), row.get(tag)
            if pv is None or rv is None:
                continue
            if tag & 0xFFFF == 0x1F:
                if not pv[1].startswith(rv):
                    err(f'message {m:#x}: contents row {tag:#010x} differs from message')
            elif i32(rv) != (pv[1] if pv[1] < 2**31 else pv[1] - 2**32):
                err(f'message {m:#x}: contents row {tag:#010x} differs from message')


# ---- Outlook / scanpst rules ------------------------------------------------
T = 0x001F
TEMPLATE = {  # required columns: Outlook's real tables and templates, and the columns scanpst names
    'hierarchy': {0x0E300102, 0x0E330014, 0x0E340102, 0x0E380003, 0x3001001F, 0x36020003, 0x36030003,
                  0x360A000B, 0x3613001F, 0x66350003, 0x66360003, 0x67F20003, 0x67F30003},
    # contents: columns present in every Outlook folder contents table, plus the two scanpst requires
    'contents': {0x00170003, 0x001A001F, 0x00360003, 0x0037001F, 0x00390040, 0x0042001F, 0x0057000B, 0x0058000B, 0x0070001F, 0x00710102, 0x0E03001F, 0x0E04001F, 0x0E060040, 0x0E070003, 0x0E080003, 0x0E170003, 0x0E300102, 0x10970003, 0x30130102, 0x65C60003, 0x67F20003, 0x67F30003},
    'assoc': {0x001A001F, 0x0E070003, 0x0E170003, 0x3001001F, 0x67F20003, 0x67F30003, 0x6800001F, 0x6803000B,
              0x68051003, 0x682F001F, 0x70030003, 0x70040102, 0x70050102, 0x7006001F, 0x70070003},
    'recipients': {0x0C150003, 0x0E0F000B, 0x0FF90102, 0x0FFE0003, 0x0FFF0102, 0x3001001F, 0x3002001F, 0x3003001F,
                   0x300B0102, 0x39000003, 0x39FF001F, 0x3A40000B, 0x67F20003, 0x67F30003},
    'attachments': {0x0E200003, 0x3704001F, 0x37050003, 0x370B0003, 0x67F20003, 0x67F30003},
}
# Columns that current scanpst (2021+) requires in contents tables but that
# files from older Outlook versions lack; scanpst simply adds them.
NEWER_SCANPST = {0x0E300102, 0x30130102}

def need_columns(path, kind, what):
    cols = COLS.get(path)
    if cols is None:
        return
    for c in sorted(TEMPLATE[kind] - cols):
        if c in NEWER_SCANPST and kind == 'contents':
            note('contents tables without the PidTagReplItemid/PidTagChangeKey columns current scanpst expects '
                 '(normal for files from older Outlook versions; scanpst adds them)')
        else:
            err(f'{what}: missing required column {c:08X} (scanpst: "TC missing required column")')

def cell_of(pt, v):
    """A PC property value as the bytes a table cell would hold."""
    if isinstance(v, bytes):
        return v
    return {0x2: struct.pack('<H', v & 0xFFFF), 0x3: struct.pack('<I', v), 0x4: struct.pack('<I', v),
            0xA: struct.pack('<I', v), 0xB: bytes([v & 0xFF])}.get(pt, b'')

def row_matches(row, props, cols, what):
    """Where the object has a property that the table has a column for, the
    row must hold the same value. (Rows may carry extra values: Outlook's own
    hierarchy rows include properties the folder objects lack.)"""
    for tag in cols:
        if tag >> 16 in (0x67F2, 0x67F3):
            continue
        pv = props.get(tag >> 16)
        if pv is None or pv[0] != tag & 0xFFFF:
            continue
        if row.get(tag) != cell_of(*pv):
            err(f'{what}: row does not match its object for column {tag:08X} (scanpst: "row doesn\'t match sub-object")')
            return

# NID high-water marks
rg = struct.unpack_from('<32I', H, 44)
for group in ((0x02, 0x0D, 0x0E, 0x0F), (0x03, 0x06, 0x07, 0x10)):
    vals = {rg[t] for t in group}
    if len(vals) != 1:
        err(f'rgnid: related NID types {[hex(t) for t in group]} have different counters {[hex(rg[t]) for t in group]} '
            f'(scanpst: "invalid high-water-mark")')
    hi = max(MAX_INDEX[t] for t in group)
    if min(rg[t] for t in group) < hi:
        err(f'rgnid: counter for NID types {[hex(t) for t in group]} is below the highest index in use {hi:#x}')
for t in range(32):
    if rg[t] < MAX_INDEX[t] and t not in (0x01, 0x11, 0x12):  # fixed special NIDs use low indexes
        err(f'rgnid[{t:#x}] = {rg[t]:#x} is below the highest index in use {MAX_INDEX[t]:#x}')

# Folders, tables and rows
for f in (n for n in nbt if n & 0x1F == NORMAL):
    if 0x3001 not in PCS.get((f,), {}):
        err(f'folder {f:#x}: missing PR_DISPLAY_NAME')
    base = f & ~0x1F
    need_columns((base | 0xD,), 'hierarchy', f'hierarchy table {base | 0xD:#x}')
    need_columns((base | 0xE,), 'contents', f'contents table {base | 0xE:#x}')
    need_columns((base | 0xF,), 'assoc', f'associated contents table {base | 0xF:#x}')
    for kid, row in TCS.get((base | 0xD,), {}).items():
        row_matches(row, PCS.get((kid,), {}), COLS[(base | 0xD,)], f'hierarchy table {base | 0xD:#x} row {kid:#x}')
    for m, row in TCS.get((base | 0xE,), {}).items():
        row_matches(row, PCS.get((m,), {}), COLS[(base | 0xE,)], f'contents table {base | 0xE:#x} row {m:#x}')
for tpl, kind in ((0x60D, 'hierarchy'), (0x60E, 'contents'), (0x60F, 'assoc'), (0x671, 'attachments'), (0x692, 'recipients')):
    need_columns((tpl,), kind, f'template table {tpl:#x}')

for m in (n for n in nbt if n & 0x1F == 0x04):
    props = PCS.get((m,), {})
    if 0x300B not in props:
        err(f'message {m:#x}: missing PR_SEARCH_KEY')
    need_columns((m, 0x692), 'recipients', f'message {m:#x} recipient table')
    need_columns((m, 0x671), 'attachments', f'message {m:#x} attachment table')
    for a, row in TCS.get((m, 0x671), {}).items():
        row_matches(row, PCS.get((m, a), {}), COLS[(m, 0x671)], f'message {m:#x} attachment table row {a:#x}')
    for path, ap in PCS.items():
        if len(path) != 2 or path[0] != m or path[1] & 0x1F != 0x05:
            continue
        total = 0
        for k, (pt, v) in ap.items():
            if pt == 0x000D and isinstance(v, bytes) and len(v) >= 8:
                total += struct.unpack_from('<I', v, 4)[0]          # embedded object: its size field
            else:
                total += len(v) if isinstance(v, bytes) else {0x2: 2, 0xB: 1}.get(pt, 4)
        size = ap.get(0x0E20, (0, None))[1]
        if size != total:
            err(f'message {m:#x} attachment {path[1]:#x}: PR_ATTACH_SIZE {size} != {total} '
                f'(scanpst: "missing or invalid PR_ATTACH_SIZE")')

# Receive folder table and search domain object
rft = TCS.get((0x62B,))
if rft is None:
    err('receive folder table (0x62B) missing')
elif not any(row.get(0x001A001F) == b'' for row in rft.values()):
    err('receive folder table has no default ("") message class (scanpst: "missing default message class")')
if 0x261 in nbt and nbt[0x261][0]:
    b = b''.join(data_tree(nbt[0x261][0]))
    if len(b) >= 4 and b[2] == 0xEC:
        err('search domain object (0x261) is a heap, not Outlook\'s format (scanpst: "Deleting SDO")')

leaked = set(bbt) - used
if leaked:
    note(f'blocks not referenced by any node: {len(leaked)} (legal; Outlook frees space lazily)')

# ------------------------------------------------------------------ allocation maps
AMAP_START, SPAN = 0x4400, 496 * 8 * 64
n_amaps = (len(data) - AMAP_START + SPAN - 1) // SPAN
FMAP_EXPECT = []
free = 0
nunits = len(data) // 64 + 1
marked = bytearray(nunits)
start = AMAP_START
for i in range(n_amaps):
    start = AMAP_START + i * SPAN
    p = data[start:start + 512]
    if len(p) < 512 or p[496] != 0x84:
        err(f'AMap {i} missing or wrong page type')
        continue
    if struct.unpack_from('<I', p, 500)[0] != crc(p[:496]):
        err(f'AMap {i}: CRC')
    if struct.unpack_from('<Q', p, 504)[0] != start:
        err(f'AMap {i}: BID')
    base = start // 64
    for byte in range(496):
        v = p[byte]
        for bit in range(8):
            if v & (0x80 >> bit):
                marked[base + byte * 8 + bit] = 1
            else:
                free += 64
    allocated.append((start, 512, 'AMap'))
    run = best = 0
    for byte in p[:496]:
        for bit in range(8):
            run = run + 1 if not byte & (0x80 >> bit) else 0
            best = max(best, run)
    FMAP_EXPECT.append(min(best, 255))
    k = 1
    if i % 8 == 0:
        allocated.append((start + 512 * k, 512, 'PMap'))
        k += 1
    if i >= 128 and (i - 128) % 496 == 0:
        allocated.append((start + 512 * k, 512, 'FMap'))
        k += 1
maps_valid = amap_valid in (1, 2)
if maps_valid:
    for i in range(128, n_amaps, 496):  # FMap pages: one byte per AMap, from the AMap that holds the page
        fm = data[AMAP_START + i * SPAN + 1024:AMAP_START + i * SPAN + 1024 + 512]
        if fm[496] != 0x82:
            err(f'FMap page missing at AMap {i}')
            continue
        if struct.unpack_from('<I', fm, 500)[0] != crc(fm[:496]):
            err(f'FMap page at AMap {i}: CRC')
        bad = [(i + k, fm[k], FMAP_EXPECT[i + k]) for k in range(min(496, n_amaps - i)) if fm[k] != FMAP_EXPECT[i + k]]
        for j, have, want in bad[:5]:
            err(f'FMap entry for AMap {j}: {have}, should be {want} (scanpst: "AMap page has csFree of {have}, but should have {want}")')
        if len(bad) > 5:
            err(f'... {len(bad) - 5} more wrong FMap entries')
if maps_valid:
    if start != amap_last:
        err(f'ibAMapLast {amap_last:#x} != last AMap {start:#x}')
    if free != amap_free:
        err(f'cbAMapFree {amap_free} != computed {free}')
else:
    note('allocation maps flagged invalid in the header (Outlook rebuilds them)')
covered = bytearray(nunits)
for ib, size, what in allocated:
    for u in range(ib // 64, (ib + size) // 64):
        if covered[u]:
            err(f'two structures overlap at {u * 64:#x} ({what})')
        covered[u] = 1
        if maps_valid and not marked[u]:
            err(f'{what} @{ib:#x} is not marked allocated in its AMap')
extra = sum(1 for u in range(nunits) if marked[u] and not covered[u])
if extra:
    note(f'AMap space marked allocated but not used by any block or page: {extra * 64} bytes')

# ------------------------------------------------------------------ report
print(f'{args[0]}: Unicode PST, encryption: {CRYPT_NAMES.get(crypt, crypt)}, {len(data):,} bytes')
print(f'  nodes={len(nbt)} blocks={len(bbt)} amaps={n_amaps} ' + ' '.join(f'{k}={v}' for k, v in sorted(stats.items())))
for kind, n in sorted(notes.items()):
    print(f'  NOTE: {kind}' + (f' [x{n}]' if n > 1 else ''))
if errors:
    import re
    kinds = Counter(re.sub(r'\b(0x)?[0-9a-fA-F]{2,}\b|\b\d+\b', '#', e) for e in errors)
    print('  ERROR summary:')
    for kind, n in kinds.most_common():
        print(f'  {n:7}x {kind}')
print('VALID' if not errors else f'{len(errors)} ERRORS')
sys.exit(1 if errors else 0)
