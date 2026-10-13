//! Turning on-disk Thunderbird folder names into Outlook folder names.
//!
//! Thunderbird folder file names can reach us in several encodings:
//! - UTF-8 (normal on Linux), possibly in decomposed form (NFD) when the
//!   profile was created on macOS ("e" + U+0301 instead of "é");
//! - legacy 8-bit Windows-1252 / Latin-1 bytes when a profile was copied
//!   from an older Windows system or through tools that do not convert names;
//! - IMAP "modified UTF-7" ([RFC 3501] 5.1.3) for IMAP folders, e.g.
//!   "Envoy&AOk-s" for "Envoyés".

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use unicode_normalization::UnicodeNormalization;

/// Decode raw bytes as UTF-8, falling back to Windows-1252 (a superset of
/// Latin-1 for printable characters).
pub fn decode_bytes(b: &[u8]) -> String {
    match std::str::from_utf8(b) {
        Ok(s) => s.to_string(),
        Err(_) => encoding_rs::WINDOWS_1252.decode_without_bom_handling(b).0.into_owned(),
    }
}

/// Strictly decode IMAP modified UTF-7. Returns None unless the input is a
/// well-formed encoding that actually contains encoded characters, so local
/// folder names such as "R&D" or "Tom&Jerry-Show" are left alone.
pub fn decode_imap_utf7(s: &str) -> Option<String> {
    if !s.contains('&') {
        return None;
    }
    let mut out = String::new();
    let mut encoded_any = false;
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        let after = &rest[amp + 1..];
        let end = after.find('-')?;
        let b64 = &after[..end];
        rest = &after[end + 1..];
        if b64.is_empty() {
            out.push('&'); // "&-" is a literal ampersand
            continue;
        }
        // Base64 with ',' instead of '/', no padding.
        let mut bits: u32 = 0;
        let mut nbits = 0;
        let mut units = Vec::new();
        for c in b64.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b',' => 63,
                _ => return None,
            } as u32;
            bits = (bits << 6) | v;
            nbits += 6;
            if nbits >= 16 {
                nbits -= 16;
                units.push((bits >> nbits) as u16);
                bits &= (1 << nbits) - 1;
            }
        }
        // Leftover bits must be fewer than 6 and all zero.
        if units.is_empty() || nbits >= 6 || bits != 0 {
            return None;
        }
        let decoded = String::from_utf16(&units).ok()?;
        // Printable ASCII is never base64-encoded in modified UTF-7.
        if decoded.chars().any(|c| (' '..='~').contains(&c)) {
            return None;
        }
        out.push_str(&decoded);
        encoded_any = true;
    }
    out.push_str(rest);
    if encoded_any {
        Some(out)
    } else {
        None
    }
}

/// Clean a decoded name for use as an Outlook folder display name.
pub fn clean_folder_name(s: &str) -> String {
    let s = decode_imap_utf7(s).unwrap_or_else(|| s.to_string());
    let s: String = s
        .nfc()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let s = s.trim().to_string();
    if s.is_empty() {
        "Unnamed folder".to_string()
    } else {
        s
    }
}

/// Folder display name for an on-disk file or directory name.
pub fn folder_name(os: &OsStr) -> String {
    clean_folder_name(&decode_bytes(os.as_bytes()))
}

/// Compose decomposed characters (NFC), used for attachment names too.
pub fn nfc(s: &str) -> String {
    s.nfc().collect()
}

/// Case-insensitive comparison key for duplicate folder names (Outlook
/// compares folder names case-insensitively, including accented letters).
pub fn folder_key(s: &str) -> String {
    s.nfc().collect::<String>().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf7() {
        assert_eq!(decode_imap_utf7("Envoy&AOk-s").as_deref(), Some("Envoyés"));
        assert_eq!(decode_imap_utf7("&AMk-l&AOk-ments envoy&AOk-s").as_deref(), Some("Éléments envoyés"));
        assert_eq!(decode_imap_utf7("R&D"), None);
        assert_eq!(decode_imap_utf7("Tom&Jerry-Show"), None);
        assert_eq!(decode_imap_utf7("A&-B"), None);
    }

    #[test]
    fn bytes_and_nfc() {
        assert_eq!(folder_name(OsStr::from_bytes(b"Soci\xe9t\xe9 G\xe9n\xe9rale")), "Société Générale");
        assert_eq!(folder_name(OsStr::from_bytes("Rec\u{327}us e\u{301}te\u{301}".as_bytes())), "Reçus été");
        assert_eq!(folder_name(OsStr::from_bytes(b"  Trailing  ")), "Trailing");
        assert_eq!(folder_key("ÉTÉ"), folder_key("e\u{301}te\u{301}"));
    }
}
