# mbox2pst

Convert a Thunderbird mail directory (mbox files) into an Outlook Unicode PST file, on Linux, without Outlook or any Windows components.

The PST writer is implemented from Microsoft's published [MS-PST] specification, covering the NDB layer (blocks, data trees, subnode trees, NBT/BBT B-trees, allocation maps, header), the LTP layer (heap-on-node, BTree-on-heap, property and table contexts) and the messaging layer (message store, folders, hierarchy/contents tables, messages, recipients, attachments, named-property map).

## Building

You need a Rust toolchain, version 1.75 or newer. On Debian or Ubuntu:

```sh
sudo apt install cargo        # or install via https://rustup.rs
cargo build --release
```

The binary is `target/release/mbox2pst`. `Cargo.lock` pins dependency versions that still build on Rust 1.75; with a newer toolchain you may run `cargo update` freely. The only runtime dependency is libc.

## Usage

```
mbox2pst [OPTIONS] <INPUT> <OUTPUT.pst>
```

| Option | Meaning |
| --- | --- |
| `-n, --name <NAME>` | Display name of the PST in Outlook (default `Thunderbird Import`) |
| `--include-deleted` | Also import messages Thunderbird marked as deleted but has not compacted away yet |
| `--keep-trash` | Import a top-level `Trash` as an ordinary folder instead of merging it into "Deleted Items" |
| `-f, --force` | Overwrite an existing output file |
| `-q, --quiet` | Only print the final summary and errors |

`INPUT` may be:

- a Thunderbird account folder directory, such as `~/.thunderbird/xxxx.default-release/Mail/Local Folders` or `.../ImapMail/imap.example.com`;
- a directory containing several of those, such as the profile's `Mail` directory, in which case each account becomes a top-level folder;
- a single mbox file.

Examples:

```sh
mbox2pst "~/.thunderbird/abcd.default-release/Mail/Local Folders" archive.pst
mbox2pst -n "Old Thunderbird Mail" ~/.thunderbird/abcd.default-release/Mail everything.pst
```

Close Thunderbird (or at least run *File → Compact Folders*) before converting, so the mbox files are stable and deleted messages are purged. For IMAP accounts, only messages Thunderbird has downloaded for offline use are present in the local mbox files.

## What is converted

Folders are discovered the way Thunderbird stores them: folder `X` is the mbox file `X` (with an `X.msf` index) and its subfolders live in `X.sbd/`. Empty folders are kept. Index files, filter rules and other non-mail files are ignored.

Folder names are read from disk as raw bytes, so every folder is opened exactly as stored, whatever its encoding. For display in Outlook, names are decoded as UTF-8, or as Windows-1252 when they are legacy 8-bit names (profiles copied from older Windows systems). IMAP folder names stored in modified UTF-7 (`Envoy&AOk-s`) are decoded to `Envoyés`. Names are normalized to composed Unicode (NFC), so decomposed macOS-style names display correctly, and leading/trailing whitespace is trimmed. Sibling folders whose names differ only by case, accents' Unicode form or such trimming get a numeric suffix such as `Été (2)`, since Outlook does not allow duplicates.

For each message the PST gets the subject, sender, To/Cc/Bcc recipients (with SMTP one-off entry IDs so replying works), sent/received date, the complete original Internet headers, Message-ID / In-Reply-To / References, importance (from `X-Priority` or `Importance`), read/unread and flagged state (from `X-Mozilla-Status`), the plain-text body, the HTML body and all attachments.

HTML bodies keep their original bytes and character set, which avoids mojibake from `<meta charset>` tags. When a message has only HTML, a plain-text version is generated for search and preview. Inline images keep their Content-ID so they render inside the HTML. Attached and forwarded messages (`message/rfc822`) become `.eml` attachments named after their subject. RFC 2047 and RFC 2231 encoded subjects, names and filenames are decoded.

A message that cannot be parsed at all is still imported: it gets the subject "(unreadable message)" and the original is attached as `original.eml`, so nothing is silently lost.

## Verifying the result

The output has been verified with two independent PST readers, libpff (`pffexport`, `pypff`) and libpst (`readpst`), and with the strict structural validator in `tools/`.

It has not been opened in Microsoft Outlook during development. Before migrating important mail, open the PST in Outlook (*File → Open & Export → Open Outlook Data File*) and run the Inbox Repair Tool, `scanpst.exe`, on a copy of it. If scanpst reports problems, please report its log.

To check a PST on Linux:

```sh
sudo apt install pff-tools pst-utils
pffinfo out.pst
pffexport -m all -t export out.pst
readpst -D -M -o export2 out.pst
python3 tools/validate_pst.py out.pst
```

`tools/validate_pst.py` checks the physical structure: header and page CRCs, page and block signatures, every block trailer, the NBT/BBT B-trees, data and subnode trees, every heap, BTH, property context and table context, and the allocation maps.

It also checks the rules Outlook and its Inbox Repair Tool (`scanpst.exe`) enforce beyond the published specification. These were established from scanpst reports and from PST files created by Outlook itself:

- every block holds 1-8176 bytes, and every block of a multi-block node except the last is full;
- BTH keys are non-zero;
- the header's NID counters cover every NID in use, with related NID types sharing one counter;
- FMap entries hold the longest free run of their allocation map;
- tables carry the columns scanpst requires;
- table rows match the folders, messages and attachments they describe;
- `PR_ATTACH_SIZE` equals the total size of the attachment's properties;
- messages have `PR_SEARCH_KEY` and folders have `PR_DISPLAY_NAME`;
- the receive-folder table has a default entry;
- folder message, unread and subfolder counts are correct.

The validator also works on PSTs created or modified by Outlook. It decodes Outlook's compressible and high encryption, and it understands the structures Outlook adds, such as search folders, nodes without data, and Outlook-internal heap types. Spec and scanpst violations are reported as `ERROR`; legal but notable conditions as `NOTE`. A summary groups errors by kind. Genuine Outlook-created PSTs validate cleanly. ANSI (Outlook 97-2002) PSTs and the 4K-page OST format are reported as unsupported rather than validated.

`tools/make_test_mail.py DIR` generates a Thunderbird-style test directory full of edge cases.

## Limitations

- The PST is written unencrypted (`NDB_CRYPT_NONE`).
- Thunderbird tags/keywords are not converted to Outlook categories, and Thunderbird's "replied"/"forwarded" state is not carried over.
- Calendar, contacts and newsgroup data are not converted; only mail folders.
- No RTF body is written. Outlook displays the HTML or plain-text body instead.
- A PST is typically about three times the size of the source mbox data, because Outlook stores text as UTF-16 and keeps headers separately. Outlook's default PST size limit is 50 GB; the tool warns if the output exceeds it.
- Each node's data must stay under 4 GiB, so single attachments larger than that are rejected.

## Source layout

| File | Contents |
| --- | --- |
| `src/main.rs` | Command line, Thunderbird folder discovery, conversion loop |
| `src/mbox.rs` | Streaming mbox reader |
| `src/names.rs` | Folder-name decoding (UTF-8 / Windows-1252, IMAP modified UTF-7, NFC) |
| `src/mime.rs` | MIME parsing, address and date handling, charset to code page mapping |
| `src/pst.rs` | Messaging layer: store, folders, messages, recipients, attachments |
| `src/ltp.rs` | LTP layer: heap-on-node, BTree-on-heap, property and table contexts |
| `src/ndb.rs` | NDB layer: blocks, B-trees, allocation maps, header |
| `src/crc.rs` | PST CRC-32 |

