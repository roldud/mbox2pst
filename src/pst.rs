//! Messaging layer ([MS-PST] section 2.4): message store, folders, messages,
//! recipients and attachments, built on top of the LTP and NDB layers.

use crate::ltp::{build_pc, build_tc, utf16le, PropList, TableRow, Value};
use crate::ltp::{PT_BINARY, PT_BOOL, PT_I32, PT_I64, PT_MV_I32, PT_STRING, PT_TIME};
use crate::ndb::{NdbWriter, SubNode};
use std::io;
use std::path::Path;

// Special NIDs.
const NID_MESSAGE_STORE: u32 = 0x21;
const NID_NAME_TO_ID_MAP: u32 = 0x61;
const NID_NORMAL_FOLDER_TEMPLATE: u32 = 0xA1;
const NID_SEARCH_FOLDER_TEMPLATE: u32 = 0xC1;
const NID_ROOT_FOLDER: u32 = 0x122;
const NID_SEARCH_MANAGEMENT_QUEUE: u32 = 0x1E1;
const NID_SEARCH_ACTIVITY_LIST: u32 = 0x201;
#[allow(dead_code)]
const NID_SEARCH_DOMAIN_OBJECT: u32 = 0x261;
const NID_SEARCH_GATHERER_QUEUE: u32 = 0x281;
#[allow(dead_code)]
const NID_SEARCH_GATHERER_DESCRIPTOR: u32 = 0x2A1;
const NID_SEARCH_GATHERER_FOLDER_QUEUE: u32 = 0x321;
const NID_HIERARCHY_TABLE_TEMPLATE: u32 = 0x60D;
const NID_CONTENTS_TABLE_TEMPLATE: u32 = 0x60E;
const NID_ASSOC_CONTENTS_TABLE_TEMPLATE: u32 = 0x60F;
const NID_SEARCH_CONTENTS_TABLE_TEMPLATE: u32 = 0x610;
const NID_ATTACHMENT_TABLE: u32 = 0x671;
const NID_RECIPIENT_TABLE: u32 = 0x692;
const NID_RECEIVE_FOLDER_TABLE: u32 = 0x62B;
const NID_OUTGOING_QUEUE_TABLE: u32 = 0x64C;

const NID_TYPE_NORMAL_FOLDER: u32 = 0x02;
const NID_TYPE_NORMAL_MESSAGE: u32 = 0x04;
const NID_TYPE_ATTACHMENT: u32 = 0x05;
const NID_TYPE_HIERARCHY_TABLE: u32 = 0x0D;
const NID_TYPE_CONTENTS_TABLE: u32 = 0x0E;
const NID_TYPE_ASSOC_CONTENTS_TABLE: u32 = 0x0F;

fn nid(index: u32, t: u32) -> u32 {
    (index << 5) | t
}

// Property IDs.
const PR_IMPORTANCE: u16 = 0x0017;
const PR_MESSAGE_CLASS: u16 = 0x001A;
const PR_SENSITIVITY: u16 = 0x0036;
const PR_SUBJECT: u16 = 0x0037;
const PR_CLIENT_SUBMIT_TIME: u16 = 0x0039;
const PR_SENT_REPRESENTING_SEARCH_KEY: u16 = 0x003B;
const PR_SENT_REPRESENTING_ENTRYID: u16 = 0x0041;
const PR_SENT_REPRESENTING_NAME: u16 = 0x0042;
const PR_MESSAGE_TO_ME: u16 = 0x0057;
const PR_MESSAGE_CC_ME: u16 = 0x0058;
const PR_SENT_REPRESENTING_ADDRTYPE: u16 = 0x0064;
const PR_SENT_REPRESENTING_EMAIL: u16 = 0x0065;
const PR_CONVERSATION_TOPIC: u16 = 0x0070;
const PR_CONVERSATION_INDEX: u16 = 0x0071;
const PR_TRANSPORT_MESSAGE_HEADERS: u16 = 0x007D;
const PR_SENDER_ENTRYID: u16 = 0x0C19;
const PR_SENDER_NAME: u16 = 0x0C1A;
const PR_SENDER_SEARCH_KEY: u16 = 0x0C1D;
const PR_SENDER_ADDRTYPE: u16 = 0x0C1E;
const PR_SENDER_EMAIL: u16 = 0x0C1F;
const PR_RECIPIENT_TYPE: u16 = 0x0C15;
const PR_DISPLAY_BCC: u16 = 0x0E02;
const PR_DISPLAY_CC: u16 = 0x0E03;
const PR_DISPLAY_TO: u16 = 0x0E04;
const PR_MESSAGE_DELIVERY_TIME: u16 = 0x0E06;
const PR_MESSAGE_FLAGS: u16 = 0x0E07;
const PR_MESSAGE_SIZE: u16 = 0x0E08;
const PR_RESPONSIBILITY: u16 = 0x0E0F;
const PR_MESSAGE_STATUS: u16 = 0x0E17;
const PR_HASATTACH: u16 = 0x0E1B;
const PR_ATTACH_SIZE: u16 = 0x0E20;
const PR_RECORD_KEY: u16 = 0x0FF9;
const PR_OBJECT_TYPE: u16 = 0x0FFE;
const PR_ENTRYID: u16 = 0x0FFF;
const PR_BODY: u16 = 0x1000;
const PR_HTML: u16 = 0x1013;
const PR_INTERNET_MESSAGE_ID: u16 = 0x1035;
const PR_INTERNET_REFERENCES: u16 = 0x1039;
const PR_IN_REPLY_TO_ID: u16 = 0x1042;
const PR_FLAG_STATUS: u16 = 0x1090;
const PR_ITEM_TEMPORARY_FLAGS: u16 = 0x1097;
const PR_DISPLAY_NAME: u16 = 0x3001;
const PR_ADDRTYPE: u16 = 0x3002;
const PR_EMAIL_ADDRESS: u16 = 0x3003;
const PR_CREATION_TIME: u16 = 0x3007;
const PR_LAST_MODIFICATION_TIME: u16 = 0x3008;
const PR_SEARCH_KEY: u16 = 0x300B;
const PR_VALID_FOLDER_MASK: u16 = 0x35DF;
const PR_IPM_SUBTREE_ENTRYID: u16 = 0x35E0;
const PR_IPM_WASTEBASKET_ENTRYID: u16 = 0x35E3;
const PR_FINDER_ENTRYID: u16 = 0x35E7;
const PR_CONTENT_COUNT: u16 = 0x3602;
const PR_CONTENT_UNREAD: u16 = 0x3603;
const PR_SUBFOLDERS: u16 = 0x360A;
const PR_CONTAINER_CLASS: u16 = 0x3613;
const PR_ATTACH_DATA_BIN: u16 = 0x3701;
const PR_ATTACH_EXTENSION: u16 = 0x3703;
const PR_ATTACH_FILENAME: u16 = 0x3704;
const PR_ATTACH_METHOD: u16 = 0x3705;
const PR_ATTACH_LONG_FILENAME: u16 = 0x3707;
const PR_RENDERING_POSITION: u16 = 0x370B;
const PR_ATTACH_MIME_TAG: u16 = 0x370E;
const PR_ATTACH_CONTENT_ID: u16 = 0x3712;
const PR_ATTACH_FLAGS: u16 = 0x3714;
const PR_DISPLAY_TYPE: u16 = 0x3900;
const PR_SMTP_ADDRESS: u16 = 0x39FE;
const PR_7BIT_DISPLAY_NAME: u16 = 0x39FF;
const PR_SEND_RICH_INFO: u16 = 0x3A40;
const PR_INTERNET_CPID: u16 = 0x3FDE;
const PR_SENDER_SMTP_ADDRESS: u16 = 0x5D01;
const PR_SENT_REPRESENTING_SMTP_ADDRESS: u16 = 0x5D02;
const PR_RECIPIENT_DISPLAY_NAME: u16 = 0x5FF6;
const PR_RECIPIENT_FLAGS: u16 = 0x5FFD;
const PR_RECIPIENT_TRACK_STATUS: u16 = 0x5FFF;
const PR_SECURE_SUBMIT_FLAGS: u16 = 0x65C6;
const PR_PST_HIDDEN_COUNT: u16 = 0x6635;
const PR_PST_HIDDEN_UNREAD: u16 = 0x6636;
const PR_PST_PASSWORD: u16 = 0x67FF;
const PR_ATTACHMENT_HIDDEN: u16 = 0x7FFE;

const PR_NAMEID_BUCKET_COUNT: u16 = 0x0001;
const PR_NAMEID_STREAM_GUID: u16 = 0x0002;
const PR_NAMEID_STREAM_ENTRY: u16 = 0x0003;
const PR_NAMEID_STREAM_STRING: u16 = 0x0004;

const MSGFLAG_READ: i32 = 0x01;
const MSGFLAG_HASATTACH: i32 = 0x10;

pub const RECIP_TO: i32 = 1;
pub const RECIP_CC: i32 = 2;
pub const RECIP_BCC: i32 = 3;

pub struct Recipient {
    pub name: String,
    pub email: String,
    pub kind: i32,
}

pub struct Attachment {
    pub filename: String,
    pub mime_type: String,
    pub data: Vec<u8>,
    pub content_id: Option<String>,
}

#[derive(Default)]
pub struct Message {
    pub subject: String,
    pub from_name: String,
    pub from_email: String,
    pub recipients: Vec<Recipient>,
    /// Date as a Windows FILETIME.
    pub date: u64,
    pub headers: String,
    pub body: Option<String>,
    /// HTML body bytes and their Windows code page.
    pub html: Option<(Vec<u8>, i32)>,
    pub message_id: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Option<String>,
    pub attachments: Vec<Attachment>,
    pub read: bool,
    pub flagged: bool,
    pub importance: i32,
    pub size: u32,
}

struct Folder {
    nid: u32,
    parent: usize,
    name: String,
    container_class: Option<&'static str>,
    children: Vec<usize>,
    rows: Vec<TableRow>,
    count: i32,
    unread: i32,
}

pub struct PstWriter {
    ndb: NdbWriter,
    store_uid: [u8; 16],
    display_name: String,
    folders: Vec<Folder>,
    next_folder_index: u32,
    next_message_index: u32,
}

/// Index of the root folder (not visible in Outlook).
pub const FOLDER_ROOT: usize = 0;
/// Index of "Top of Personal Folders" (the visible root of the store).
pub const FOLDER_TOP: usize = 1;
/// Index of "Deleted Items".
pub const FOLDER_DELETED_ITEMS: usize = 3;

fn random_uid() -> [u8; 16] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut out = [0u8; 16];
    for half in 0..2 {
        let mut h = RandomState::new().build_hasher();
        h.write_u128(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos());
        h.write_u32(std::process::id());
        h.write_usize(half);
        out[half * 8..half * 8 + 8].copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

/// One-off EntryID ([MS-OXCDATA] 2.2.5.1) for an SMTP address.
fn one_off_entry_id(name: &str, email: &str) -> Vec<u8> {
    let mut v = vec![0u8; 4];
    v.extend_from_slice(&[0x81, 0x2B, 0x1F, 0xA4, 0xBE, 0xA3, 0x10, 0x19, 0x9D, 0x6E, 0x00, 0xDD, 0x01, 0x0F, 0x54, 0x02]);
    v.extend_from_slice(&[0x00, 0x00, 0x01, 0x90]); // version 0; no rich info, Unicode
    for s in [if name.is_empty() { email } else { name }, "SMTP", email] {
        v.extend_from_slice(&utf16le(s));
        v.extend_from_slice(&[0, 0]);
    }
    v
}

fn search_key(email: &str) -> Vec<u8> {
    let mut v = format!("SMTP:{}", email.to_uppercase()).into_bytes();
    v.push(0);
    v
}

/// Strip "Re:", "Fwd:" etc. to form the conversation topic.
fn conversation_topic(subject: &str) -> String {
    let mut s = subject.trim();
    loop {
        let lower = s.to_lowercase();
        let mut stripped = false;
        for p in ["re:", "fw:", "fwd:", "aw:", "wg:", "sv:", "vs:", "tr:", "rif:", "antw:"] {
            if lower.starts_with(p) {
                s = s[p.len()..].trim_start();
                stripped = true;
                break;
            }
        }
        if !stripped {
            return s.to_string();
        }
    }
}

fn short_filename(long: &str) -> String {
    let (stem, ext) = match long.rfind('.') {
        Some(i) if i > 0 => (&long[..i], &long[i + 1..]),
        _ => (long, ""),
    };
    let clean = |s: &str, n: usize| -> String {
        s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(n).collect::<String>().to_uppercase()
    };
    let mut st = clean(stem, 8);
    if st.is_empty() {
        st = "ATTACH".into();
    }
    let ex = clean(ext, 3);
    if ex.is_empty() {
        st
    } else {
        format!("{}.{}", st, ex)
    }
}

// Table schemas, taken from the template tables of PST files created by
// Outlook (nodes 0x60D, 0x60E, 0x60F, 0x610, 0x671, 0x692, 0x62B, 0x64C).
// scanpst reports "TC missing required column" when any of these is absent.
// The mandatory row-id/row-version columns are added by build_tc.
const HIERARCHY_COLUMNS: &[(u16, u16)] = &[
    (0x0E30, PT_BINARY), // PidTagReplItemid
    (0x0E33, PT_I64),    // PidTagReplChangenum
    (0x0E34, PT_BINARY), // PidTagReplVersionhistory
    (0x0E38, PT_I32),    // PidTagReplFlags
    (PR_DISPLAY_NAME, PT_STRING),
    (PR_CONTENT_COUNT, PT_I32),
    (PR_CONTENT_UNREAD, PT_I32),
    (PR_SUBFOLDERS, PT_BOOL),
    (PR_CONTAINER_CLASS, PT_STRING),
    (PR_PST_HIDDEN_COUNT, PT_I32),
    (PR_PST_HIDDEN_UNREAD, PT_I32),
];

const CONTENTS_COLUMNS: &[(u16, u16)] = &[
    (PR_IMPORTANCE, PT_I32),
    (PR_MESSAGE_CLASS, PT_STRING),
    (PR_SENSITIVITY, PT_I32),
    (PR_SUBJECT, PT_STRING),
    (PR_CLIENT_SUBMIT_TIME, PT_TIME),
    (PR_SENT_REPRESENTING_NAME, PT_STRING),
    (PR_MESSAGE_TO_ME, PT_BOOL),
    (PR_MESSAGE_CC_ME, PT_BOOL),
    (PR_CONVERSATION_TOPIC, PT_STRING),
    (PR_CONVERSATION_INDEX, PT_BINARY),
    (PR_DISPLAY_CC, PT_STRING),
    (PR_DISPLAY_TO, PT_STRING),
    (PR_MESSAGE_DELIVERY_TIME, PT_TIME),
    (PR_MESSAGE_FLAGS, PT_I32),
    (PR_MESSAGE_SIZE, PT_I32),
    (PR_MESSAGE_STATUS, PT_I32),
    (0x0E30, PT_BINARY), // PidTagReplItemid
    (0x0E33, PT_I64),    // PidTagReplChangenum
    (0x0E34, PT_BINARY), // PidTagReplVersionhistory
    (0x0E38, PT_I32),    // PidTagReplFlags
    (0x0E3C, PT_BINARY), // PidTagReplCopiedfromVersionhistory
    (0x0E3D, PT_BINARY), // PidTagReplCopiedfromItemid
    (PR_ITEM_TEMPORARY_FLAGS, PT_I32),
    (PR_LAST_MODIFICATION_TIME, PT_TIME),
    (0x3013, PT_BINARY), // PidTagChangeKey
    (PR_SECURE_SUBMIT_FLAGS, PT_I32),
];

const ASSOC_CONTENTS_COLUMNS: &[(u16, u16)] = &[
    (PR_MESSAGE_CLASS, PT_STRING),
    (PR_MESSAGE_FLAGS, PT_I32),
    (PR_MESSAGE_STATUS, PT_I32),
    (PR_DISPLAY_NAME, PT_STRING),
    (0x6800, PT_STRING),    // PidTagOfflineAddressBookName
    (0x6803, PT_BOOL),      // PidTagSendOutlookRecallReport
    (0x6805, PT_MV_I32),    // PidTagOfflineAddressBookTruncatedProperties
    (0x682F, PT_STRING),    // PidTagOfflineAddressBookContainerGuid
    (0x7003, PT_I32),       // PidTagViewDescriptorFlags
    (0x7004, PT_BINARY),    // PidTagViewDescriptorLinkTo
    (0x7005, PT_BINARY),    // PidTagViewDescriptorViewFolder
    (0x7006, PT_STRING),    // PidTagViewDescriptorName
    (0x7007, PT_I32),       // PidTagViewDescriptorVersion
];

const SEARCH_CONTENTS_COLUMNS: &[(u16, u16)] = &[
    (PR_IMPORTANCE, PT_I32),
    (PR_MESSAGE_CLASS, PT_STRING),
    (PR_SENSITIVITY, PT_I32),
    (PR_SUBJECT, PT_STRING),
    (PR_SENT_REPRESENTING_NAME, PT_STRING),
    (PR_MESSAGE_TO_ME, PT_BOOL),
    (PR_MESSAGE_CC_ME, PT_BOOL),
    (PR_DISPLAY_CC, PT_STRING),
    (PR_DISPLAY_TO, PT_STRING),
    (0x0E05, PT_STRING), // PidTagParentDisplay
    (PR_MESSAGE_DELIVERY_TIME, PT_TIME),
    (PR_MESSAGE_FLAGS, PT_I32),
    (PR_MESSAGE_SIZE, PT_I32),
    (PR_MESSAGE_STATUS, PT_I32),
    (0x0E2A, PT_BOOL),   // PidTagExchangeRemoteHeader
    (PR_LAST_MODIFICATION_TIME, PT_TIME),
    (0x67F1, PT_I32),    // PidTagLtpParentNid
];

/// Recipient table: Outlook's template columns plus a few extra properties
/// (tables may carry more columns than their template).
const RECIPIENT_COLUMNS: &[(u16, u16)] = &[
    (PR_RECIPIENT_TYPE, PT_I32),
    (PR_RESPONSIBILITY, PT_BOOL),
    (PR_RECORD_KEY, PT_BINARY),
    (PR_OBJECT_TYPE, PT_I32),
    (PR_ENTRYID, PT_BINARY),
    (PR_DISPLAY_NAME, PT_STRING),
    (PR_ADDRTYPE, PT_STRING),
    (PR_EMAIL_ADDRESS, PT_STRING),
    (PR_SEARCH_KEY, PT_BINARY),
    (PR_DISPLAY_TYPE, PT_I32),
    (PR_7BIT_DISPLAY_NAME, PT_STRING),
    (PR_SEND_RICH_INFO, PT_BOOL),
    (PR_SMTP_ADDRESS, PT_STRING),
    (PR_RECIPIENT_DISPLAY_NAME, PT_STRING),
    (PR_RECIPIENT_FLAGS, PT_I32),
    (PR_RECIPIENT_TRACK_STATUS, PT_I32),
];

const ATTACHMENT_COLUMNS: &[(u16, u16)] = &[
    (PR_ATTACH_SIZE, PT_I32),
    (PR_ATTACH_FILENAME, PT_STRING),
    (PR_ATTACH_METHOD, PT_I32),
    (PR_RENDERING_POSITION, PT_I32),
];

const RECEIVE_FOLDER_COLUMNS: &[(u16, u16)] = &[(PR_MESSAGE_CLASS, PT_STRING), (0x6605, PT_I32)]; // PidTagPstReceiveFolderNid
const OUTGOING_QUEUE_COLUMNS: &[(u16, u16)] = &[(PR_CLIENT_SUBMIT_TIME, PT_TIME), (0x0E10, PT_I32), (0x0E14, PT_I32)];

/// A table row holding exactly those of the object's properties that the
/// table has columns for, so rows always match their objects (scanpst
/// reports "row doesn't match sub-object" otherwise).
fn project(row_id: u32, props: &PropList, columns: &[(u16, u16)]) -> TableRow {
    let values = props
        .iter()
        .filter(|(id, v)| columns.iter().any(|&(cid, ct)| cid == *id && ct == v.ptype()))
        .cloned()
        .collect();
    TableRow { row_id, values }
}

impl PstWriter {
    pub fn create(path: &Path, display_name: &str) -> io::Result<Self> {
        let mut w = PstWriter {
            ndb: NdbWriter::create(path)?,
            store_uid: random_uid(),
            display_name: display_name.to_string(),
            folders: Vec::new(),
            next_folder_index: 0x401,
            next_message_index: 0x10000,
        };
        w.folders.push(Folder {
            nid: NID_ROOT_FOLDER,
            parent: FOLDER_ROOT,
            name: String::new(),
            container_class: None,
            children: Vec::new(),
            rows: Vec::new(),
            count: 0,
            unread: 0,
        });
        let top = w.add_folder_with_class(FOLDER_ROOT, "Top of Personal Folders", None);
        let search = w.add_folder_with_class(FOLDER_ROOT, "Search Root", None);
        let deleted = w.add_folder(top, "Deleted Items");
        debug_assert_eq!((top, search, deleted), (FOLDER_TOP, 2, FOLDER_DELETED_ITEMS));
        Ok(w)
    }

    fn entry_id(&self, nid: u32) -> Vec<u8> {
        let mut v = vec![0u8; 4];
        v.extend_from_slice(&self.store_uid);
        v.extend_from_slice(&nid.to_le_bytes());
        v
    }

    fn add_folder_with_class(&mut self, parent: usize, name: &str, class: Option<&'static str>) -> usize {
        let index = self.next_folder_index;
        self.next_folder_index += 1;
        self.folders.push(Folder {
            nid: nid(index, NID_TYPE_NORMAL_FOLDER),
            parent,
            name: name.to_string(),
            container_class: class,
            children: Vec::new(),
            rows: Vec::new(),
            count: 0,
            unread: 0,
        });
        let id = self.folders.len() - 1;
        self.folders[parent].children.push(id);
        id
    }

    /// Create a mail folder below `parent`; returns its handle.
    pub fn add_folder(&mut self, parent: usize, name: &str) -> usize {
        // Outlook does not allow two sibling folders with the same name.
        let name = crate::names::clean_folder_name(name);
        let mut candidate = name.clone();
        let mut n = 2;
        while self.folders[parent]
            .children
            .iter()
            .any(|&c| crate::names::folder_key(&self.folders[c].name) == crate::names::folder_key(&candidate))
        {
            candidate = format!("{} ({})", name, n);
            n += 1;
        }
        self.add_folder_with_class(parent, &candidate, Some("IPF.Note"))
    }

    pub fn add_message(&mut self, folder: usize, m: &Message) -> io::Result<()> {
        let msg_nid = nid(self.next_message_index, NID_TYPE_NORMAL_MESSAGE);
        self.next_message_index += 1;

        let join = |kind: i32| -> String {
            m.recipients
                .iter()
                .filter(|r| r.kind == kind)
                .map(|r| if r.name.is_empty() { r.email.clone() } else { r.name.clone() })
                .collect::<Vec<_>>()
                .join("; ")
        };
        let display_to = join(RECIP_TO);
        let display_cc = join(RECIP_CC);
        let display_bcc = join(RECIP_BCC);
        let sender_name = if m.from_name.is_empty() { m.from_email.clone() } else { m.from_name.clone() };
        let mut flags = if m.read { MSGFLAG_READ } else { 0 };
        if !m.attachments.is_empty() {
            flags |= MSGFLAG_HASATTACH;
        }
        let topic = conversation_topic(&m.subject);

        let mut p: PropList = vec![
            (PR_MESSAGE_CLASS, Value::Str("IPM.Note".into())),
            (PR_SUBJECT, Value::Str(m.subject.clone())),
            (PR_CONVERSATION_TOPIC, Value::Str(topic.clone())),
            (PR_IMPORTANCE, Value::I32(m.importance)),
            (PR_SENSITIVITY, Value::I32(0)),
            (PR_CLIENT_SUBMIT_TIME, Value::Time(m.date)),
            (PR_MESSAGE_DELIVERY_TIME, Value::Time(m.date)),
            (PR_CREATION_TIME, Value::Time(m.date)),
            (PR_LAST_MODIFICATION_TIME, Value::Time(m.date)),
            (PR_MESSAGE_FLAGS, Value::I32(flags)),
            (PR_MESSAGE_SIZE, Value::I32(m.size as i32)),
            (PR_MESSAGE_STATUS, Value::I32(0)),
            (PR_HASATTACH, Value::Bool(!m.attachments.is_empty())),
            (PR_DISPLAY_TO, Value::Str(display_to.clone())),
            (PR_DISPLAY_CC, Value::Str(display_cc.clone())),
            (PR_DISPLAY_BCC, Value::Str(display_bcc)),
            (PR_TRANSPORT_MESSAGE_HEADERS, Value::Str(m.headers.clone())),
            (PR_SENDER_NAME, Value::Str(sender_name.clone())),
            (PR_SENT_REPRESENTING_NAME, Value::Str(sender_name.clone())),
        ];
        if !m.from_email.is_empty() {
            let eid = one_off_entry_id(&sender_name, &m.from_email);
            let sk = search_key(&m.from_email);
            p.extend([
                (PR_SENDER_ADDRTYPE, Value::Str("SMTP".into())),
                (PR_SENDER_EMAIL, Value::Str(m.from_email.clone())),
                (PR_SENDER_SMTP_ADDRESS, Value::Str(m.from_email.clone())),
                (PR_SENDER_ENTRYID, Value::Bin(eid.clone())),
                (PR_SENDER_SEARCH_KEY, Value::Bin(sk.clone())),
                (PR_SENT_REPRESENTING_ADDRTYPE, Value::Str("SMTP".into())),
                (PR_SENT_REPRESENTING_EMAIL, Value::Str(m.from_email.clone())),
                (PR_SENT_REPRESENTING_SMTP_ADDRESS, Value::Str(m.from_email.clone())),
                (PR_SENT_REPRESENTING_ENTRYID, Value::Bin(eid)),
                (PR_SENT_REPRESENTING_SEARCH_KEY, Value::Bin(sk)),
            ]);
        }
        if let Some(b) = &m.body {
            p.push((PR_BODY, Value::Str(b.clone())));
        }
        if let Some((h, cp)) = &m.html {
            p.push((PR_HTML, Value::Bin(h.clone())));
            p.push((PR_INTERNET_CPID, Value::I32(*cp)));
        }
        if let Some(v) = &m.message_id {
            p.push((PR_INTERNET_MESSAGE_ID, Value::Str(v.clone())));
        }
        if let Some(v) = &m.in_reply_to {
            p.push((PR_IN_REPLY_TO_ID, Value::Str(v.clone())));
        }
        if let Some(v) = &m.references {
            p.push((PR_INTERNET_REFERENCES, Value::Str(v.clone())));
        }
        if m.flagged {
            p.push((PR_FLAG_STATUS, Value::I32(2)));
        }
        // PR_SEARCH_KEY: a unique 16-byte key per message (scanpst requires it).
        p.push((PR_SEARCH_KEY, Value::Bin(self.unique_key(msg_nid))));

        // Recipient table.
        let rows: Vec<TableRow> = m
            .recipients
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let name = if r.name.is_empty() { r.email.clone() } else { r.name.clone() };
                TableRow {
                    row_id: i as u32 + 1,
                    values: vec![
                        (PR_RECIPIENT_TYPE, Value::I32(r.kind)),
                        (PR_RESPONSIBILITY, Value::Bool(false)),
                        (PR_RECORD_KEY, Value::Bin(search_key(&r.email))),
                        (PR_OBJECT_TYPE, Value::I32(6)), // MAPI_MAILUSER
                        (PR_ENTRYID, Value::Bin(one_off_entry_id(&name, &r.email))),
                        (PR_DISPLAY_NAME, Value::Str(name.clone())),
                        (PR_ADDRTYPE, Value::Str("SMTP".into())),
                        (PR_EMAIL_ADDRESS, Value::Str(r.email.clone())),
                        (PR_SEARCH_KEY, Value::Bin(search_key(&r.email))),
                        (PR_DISPLAY_TYPE, Value::I32(0)), // DT_MAILUSER
                        (PR_SMTP_ADDRESS, Value::Str(r.email.clone())),
                        (PR_7BIT_DISPLAY_NAME, Value::Str(name.clone())),
                        (PR_SEND_RICH_INFO, Value::Bool(false)),
                        (PR_RECIPIENT_DISPLAY_NAME, Value::Str(name)),
                        (PR_RECIPIENT_FLAGS, Value::I32(1)),
                        (PR_RECIPIENT_TRACK_STATUS, Value::I32(0)),
                    ],
                }
            })
            .collect();
        let mut subnodes = vec![SubNode { nid: NID_RECIPIENT_TABLE, content: build_tc(RECIPIENT_COLUMNS, &rows) }];

        // Attachments.
        if !m.attachments.is_empty() {
            let html_text = m.html.as_ref().map(|(h, _)| String::from_utf8_lossy(h).to_lowercase()).unwrap_or_default();
            let mut att_rows = Vec::new();
            for (i, a) in m.attachments.iter().enumerate() {
                let att_nid = nid(0x401 + i as u32, NID_TYPE_ATTACHMENT);
                let short = short_filename(&a.filename);
                let ext = a.filename.rfind('.').map(|i| a.filename[i..].to_string()).unwrap_or_default();
                let mut ap: PropList = vec![
                    (PR_ATTACH_METHOD, Value::I32(1)), // ATTACH_BY_VALUE
                    (PR_ATTACH_DATA_BIN, Value::Bin(a.data.clone())),
                    (PR_ATTACH_FILENAME, Value::Str(short.clone())),
                    (PR_ATTACH_LONG_FILENAME, Value::Str(a.filename.clone())),
                    (PR_ATTACH_EXTENSION, Value::Str(ext)),
                    (PR_DISPLAY_NAME, Value::Str(a.filename.clone())),
                    (PR_ATTACH_MIME_TAG, Value::Str(a.mime_type.clone())),
                    (PR_RENDERING_POSITION, Value::I32(-1)),
                    (PR_OBJECT_TYPE, Value::I32(7)), // MAPI_ATTACH
                ];
                if let Some(cid) = &a.content_id {
                    ap.push((PR_ATTACH_CONTENT_ID, Value::Str(cid.clone())));
                    if html_text.contains(&format!("cid:{}", cid.to_lowercase())) {
                        ap.push((PR_ATTACHMENT_HIDDEN, Value::Bool(true)));
                        ap.push((PR_ATTACH_FLAGS, Value::I32(4))); // ATT_MHTML_REF
                    }
                }
                // Outlook's PR_ATTACH_SIZE is the total size of all the attachment's
                // property values, including this 4-byte property itself (verified
                // against attachments in Outlook-created PSTs).
                let size = ap.iter().map(|(_, v)| v.byte_size()).sum::<usize>() + 4;
                ap.push((PR_ATTACH_SIZE, Value::I32(size.min(i32::MAX as usize) as i32)));
                att_rows.push(project(att_nid, &ap, ATTACHMENT_COLUMNS));
                subnodes.push(SubNode { nid: att_nid, content: build_pc(&ap, Vec::new()) });
            }
            subnodes.push(SubNode { nid: NID_ATTACHMENT_TABLE, content: build_tc(ATTACHMENT_COLUMNS, &att_rows) });
        }

        let row = project(msg_nid, &p, CONTENTS_COLUMNS);
        let content = build_pc(&p, subnodes);
        let f = &mut self.folders[folder];
        self.ndb.add_node(msg_nid, f.nid, &content)?;

        f.count += 1;
        if !m.read {
            f.unread += 1;
        }
        f.rows.push(row);
        Ok(())
    }

    /// A unique 16-byte key derived from the store's random UID and a NID.
    fn unique_key(&self, nid: u32) -> Vec<u8> {
        use std::hash::{Hash, Hasher};
        let mut out = Vec::with_capacity(16);
        for salt in 0..2u8 {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            (self.store_uid, nid, salt).hash(&mut h);
            out.extend_from_slice(&h.finish().to_le_bytes());
        }
        out
    }

    fn folder_props(f: &Folder, has_children: bool) -> PropList {
        // Every folder has PR_DISPLAY_NAME; the root folder's is empty, as in
        // Outlook-created stores.
        let mut p = vec![
            (PR_DISPLAY_NAME, Value::Str(f.name.clone())),
            (PR_CONTENT_COUNT, Value::I32(f.count)),
            (PR_CONTENT_UNREAD, Value::I32(f.unread)),
            (PR_SUBFOLDERS, Value::Bool(has_children)),
        ];
        if let Some(c) = f.container_class {
            p.push((PR_CONTAINER_CLASS, Value::Str(c.into())));
        }
        p
    }

    /// Write folders, tables, the message store and other mandatory nodes,
    /// then finalise the file. Returns the file size.
    pub fn finish(mut self) -> io::Result<u64> {
        let folders = std::mem::take(&mut self.folders);
        for f in &folders {
            let index = f.nid >> 5;
            self.ndb.add_node(f.nid, folders[f.parent].nid, &build_pc(&Self::folder_props(f, !f.children.is_empty()), Vec::new()))?;

            let hrows: Vec<TableRow> = f
                .children
                .iter()
                .map(|&c| {
                    let cf = &folders[c];
                    project(cf.nid, &Self::folder_props(cf, !cf.children.is_empty()), HIERARCHY_COLUMNS)
                })
                .collect();
            self.ndb.add_node(nid(index, NID_TYPE_HIERARCHY_TABLE), 0, &build_tc(HIERARCHY_COLUMNS, &hrows))?;
            self.ndb.add_node(nid(index, NID_TYPE_CONTENTS_TABLE), 0, &build_tc(CONTENTS_COLUMNS, &f.rows))?;
            self.ndb.add_node(nid(index, NID_TYPE_ASSOC_CONTENTS_TABLE), 0, &build_tc(ASSOC_CONTENTS_COLUMNS, &[]))?;
        }

        // Message store.
        let store: PropList = vec![
            (PR_RECORD_KEY, Value::Bin(self.store_uid.to_vec())),
            (PR_DISPLAY_NAME, Value::Str(self.display_name.clone())),
            (PR_IPM_SUBTREE_ENTRYID, Value::Bin(self.entry_id(folders[FOLDER_TOP].nid))),
            (PR_IPM_WASTEBASKET_ENTRYID, Value::Bin(self.entry_id(folders[FOLDER_DELETED_ITEMS].nid))),
            (PR_FINDER_ENTRYID, Value::Bin(self.entry_id(folders[2].nid))),
            (PR_VALID_FOLDER_MASK, Value::I32(0x89)), // IPM subtree, wastebasket, finder
            (PR_PST_PASSWORD, Value::I32(0)),
        ];
        self.ndb.add_node(NID_MESSAGE_STORE, 0, &build_pc(&store, Vec::new()))?;

        // Named property map ([MS-PST] 2.4.7). Outlook-created stores always
        // contain mappings; we register PidLidCurrentVersion (PSETID_Common,
        // LID 0x8552) so the streams and hash bucket are well-formed.
        const PSETID_COMMON: [u8; 16] = [0x08, 0x20, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46];
        const BUCKETS: u32 = 251;
        let lid: u32 = 0x8552;
        let guid_field: u16 = 3 << 1; // GUID index 3 = first GUID in the stream; N = 0 (numeric)
        let mut entry = lid.to_le_bytes().to_vec();
        entry.extend_from_slice(&guid_field.to_le_bytes());
        entry.extend_from_slice(&0u16.to_le_bytes()); // wPropIdx 0 -> property id 0x8000
        let bucket = ((lid ^ guid_field as u32) % BUCKETS) as u16;
        let nameid: PropList = vec![
            (PR_NAMEID_BUCKET_COUNT, Value::I32(BUCKETS as i32)),
            (PR_NAMEID_STREAM_GUID, Value::Bin(PSETID_COMMON.to_vec())),
            (PR_NAMEID_STREAM_ENTRY, Value::Bin(entry.clone())),
            (PR_NAMEID_STREAM_STRING, Value::Bin(Vec::new())),
            (0x1000 + bucket, Value::Bin(entry)),
        ];
        self.ndb.add_node(NID_NAME_TO_ID_MAP, 0, &build_pc(&nameid, Vec::new()))?;

        // Templates, as found in every Outlook-created store.
        self.ndb.add_node(NID_NORMAL_FOLDER_TEMPLATE, 0, &build_pc(&Vec::new(), Vec::new()))?;
        self.ndb.add_node(NID_SEARCH_FOLDER_TEMPLATE, 0, &build_pc(&Vec::new(), Vec::new()))?;
        self.ndb.add_node(NID_HIERARCHY_TABLE_TEMPLATE, 0, &build_tc(HIERARCHY_COLUMNS, &[]))?;
        self.ndb.add_node(NID_CONTENTS_TABLE_TEMPLATE, 0, &build_tc(CONTENTS_COLUMNS, &[]))?;
        self.ndb.add_node(NID_ASSOC_CONTENTS_TABLE_TEMPLATE, 0, &build_tc(ASSOC_CONTENTS_COLUMNS, &[]))?;
        self.ndb.add_node(NID_SEARCH_CONTENTS_TABLE_TEMPLATE, 0, &build_tc(SEARCH_CONTENTS_COLUMNS, &[]))?;
        self.ndb.add_node(NID_ATTACHMENT_TABLE, 0, &build_tc(ATTACHMENT_COLUMNS, &[]))?;
        self.ndb.add_node(NID_RECIPIENT_TABLE, 0, &build_tc(RECIPIENT_COLUMNS, &[]))?;

        // Receive folder table: which folder receives which message classes.
        // Like Outlook: "", "IPM" and "Report.IPM" go to the inbox (here the
        // top-level folder named Inbox, else the top of the store) and "IPC"
        // to the root folder. scanpst requires the default ("") entry.
        let inbox = folders[FOLDER_TOP]
            .children
            .iter()
            .map(|&c| &folders[c])
            .find(|f| f.name.eq_ignore_ascii_case("Inbox"))
            .unwrap_or(&folders[FOLDER_TOP])
            .nid;
        let receive: Vec<TableRow> = [("", inbox), ("IPM", inbox), ("Report.IPM", inbox), ("IPC", NID_ROOT_FOLDER)]
            .iter()
            .enumerate()
            .map(|(i, (class, folder))| TableRow {
                row_id: i as u32 + 1,
                values: vec![(PR_MESSAGE_CLASS, Value::Str(class.to_string())), (0x6605, Value::I32(*folder as i32))],
            })
            .collect();
        self.ndb.add_node(NID_RECEIVE_FOLDER_TABLE, 0, &build_tc(RECEIVE_FOLDER_COLUMNS, &receive))?;
        self.ndb.add_node(NID_OUTGOING_QUEUE_TABLE, 0, &build_tc(OUTGOING_QUEUE_COLUMNS, &[]))?;

        // Search queues and activity list, empty: Outlook stores empty queues as
        // nodes without data. The search domain object (0x261) and gatherer
        // descriptor (0x2A1) use Outlook-internal formats; Outlook creates them.
        for q in [NID_SEARCH_MANAGEMENT_QUEUE, NID_SEARCH_ACTIVITY_LIST, NID_SEARCH_GATHERER_QUEUE, NID_SEARCH_GATHERER_FOLDER_QUEUE] {
            self.ndb.add_empty_node(q, 0);
        }

        self.ndb.finish()
    }
}
