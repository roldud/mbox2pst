//! Converts a raw RFC 5322 / MIME message into a `pst::Message`.

use crate::mbox::RawMessage;
use crate::pst::{Attachment, Message, Recipient, RECIP_BCC, RECIP_CC, RECIP_TO};
use mailparse::{DispositionType, MailAddr, MailHeaderMap, ParsedMail};

/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_DIFF: i64 = 11_644_473_600;

pub fn unix_to_filetime(secs: i64) -> u64 {
    ((secs + EPOCH_DIFF).max(0) as u64) * 10_000_000
}

/// Thunderbird X-Mozilla-Status flags.
const MOZ_READ: u32 = 0x0001;
const MOZ_MARKED: u32 = 0x0004;
pub const MOZ_EXPUNGED: u32 = 0x0008;

pub fn mozilla_status(raw: &[u8]) -> u32 {
    let head = header_block(raw);
    for line in head.lines() {
        if let Some(v) = line.strip_prefix("X-Mozilla-Status:") {
            return u32::from_str_radix(v.trim(), 16).unwrap_or(0);
        }
    }
    0
}

/// The raw header section of a message, as text.
fn header_block(raw: &[u8]) -> String {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 2)
        .into_iter()
        .chain(raw.windows(2).position(|w| w == b"\n\n").map(|p| p + 1))
        .min()
        .unwrap_or(raw.len());
    crate::names::decode_bytes(&raw[..end])
}

/// Parse the asctime-style date in an mbox envelope line, e.g.
/// "From - Tue Jan  2 03:04:05 2024".
fn envelope_date(line: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let toks: Vec<&str> = line.split_whitespace().collect();
    let mi = toks.iter().position(|t| MONTHS.contains(&t.to_lowercase().as_str()))?;
    let month = MONTHS.iter().position(|m| *m == toks[mi].to_lowercase())? as i64 + 1;
    let day: i64 = toks.get(mi + 1)?.parse().ok()?;
    let hms: Vec<i64> = toks.get(mi + 2)?.split(':').filter_map(|x| x.parse().ok()).collect();
    let year: i64 = toks.get(mi + 3)?.parse().ok()?;
    if hms.len() < 2 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86400 + hms[0] * 3600 + hms[1] * 60 + hms.get(2).copied().unwrap_or(0))
}

/// Map a MIME charset name to a Windows code page (for PidTagInternetCodepage).
fn charset_codepage(cs: &str) -> Option<i32> {
    Some(match cs.to_ascii_lowercase().as_str() {
        "utf-8" | "utf8" => 65001,
        "us-ascii" | "ascii" => 20127,
        "iso-8859-1" | "latin1" => 28591,
        "iso-8859-2" => 28592,
        "iso-8859-3" => 28593,
        "iso-8859-4" => 28594,
        "iso-8859-5" => 28595,
        "iso-8859-6" => 28596,
        "iso-8859-7" => 28597,
        "iso-8859-8" => 28598,
        "iso-8859-9" => 28599,
        "iso-8859-13" => 28603,
        "iso-8859-15" => 28605,
        "windows-1250" => 1250,
        "windows-1251" => 1251,
        "windows-1252" => 1252,
        "windows-1253" => 1253,
        "windows-1254" => 1254,
        "windows-1255" => 1255,
        "windows-1256" => 1256,
        "windows-1257" => 1257,
        "windows-1258" => 1258,
        "koi8-r" => 20866,
        "koi8-u" => 21866,
        "shift_jis" | "shift-jis" | "sjis" => 932,
        "euc-jp" => 51932,
        "iso-2022-jp" => 50220,
        "gb2312" | "gbk" => 936,
        "gb18030" => 54936,
        "big5" => 950,
        "euc-kr" => 51949,
        "ks_c_5601-1987" => 949,
        _ => return None,
    })
}

fn extension_for(mime: &str) -> &'static str {
    match mime {
        "image/jpeg" | "image/jpg" | "image/pjpeg" => "jpg",
        "image/png" => "png",
        "image/gif" => "gif",
        "image/bmp" => "bmp",
        "image/webp" => "webp",
        "image/svg+xml" => "svg",
        "image/tiff" => "tif",
        "application/pdf" => "pdf",
        "application/zip" => "zip",
        "text/plain" => "txt",
        "text/html" => "html",
        "text/csv" => "csv",
        "text/calendar" => "ics",
        "text/vcard" | "text/x-vcard" => "vcf",
        "message/rfc822" => "eml",
        "message/delivery-status" => "txt",
        "application/pgp-signature" => "asc",
        "application/pkcs7-signature" | "application/x-pkcs7-signature" => "p7s",
        _ => "bin",
    }
}

/// Decode RFC 2047 encoded words that sometimes appear in parameters.
fn decode_words(s: &str) -> String {
    if !s.contains("=?") {
        return s.to_string();
    }
    match mailparse::parse_header(format!("X: {}", s).as_bytes()) {
        Ok((h, _)) => h.get_value(),
        Err(_) => s.to_string(),
    }
}

/// Make a file name safe for Windows.
fn sanitize_filename(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() || "\\/:*?\"<>|".contains(c) { '_' } else { c })
        .collect();
    cleaned.trim().trim_matches('.').to_string()
}

/// Very small HTML-to-text conversion used when a message has no text part.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let mut chars = html.chars().peekable();
    let mut skip_until: Option<&str> = None;
    while let Some(c) = chars.next() {
        if c == '<' {
            let mut tag = String::new();
            for t in chars.by_ref() {
                if t == '>' {
                    break;
                }
                tag.push(t);
            }
            let name: String = tag
                .trim_start_matches('/')
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if let Some(end) = skip_until {
                if tag.starts_with('/') && name == end {
                    skip_until = None;
                }
                continue;
            }
            match name.as_str() {
                "script" | "style" | "head" if !tag.starts_with('/') => {
                    skip_until = Some(match name.as_str() {
                        "script" => "script",
                        "style" => "style",
                        _ => "head",
                    })
                }
                "br" | "p" | "div" | "tr" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "blockquote" => out.push('\n'),
                "td" | "th" => out.push('\t'),
                _ => {}
            }
        } else if skip_until.is_some() {
            continue;
        } else if c == '&' {
            let mut ent = String::new();
            while let Some(&n) = chars.peek() {
                if n == ';' || ent.len() > 8 || n.is_whitespace() || n == '<' {
                    break;
                }
                ent.push(n);
                chars.next();
            }
            let semi = chars.peek() == Some(&';');
            if semi {
                chars.next();
            }
            let rep = match ent.as_str() {
                "nbsp" => Some(' '),
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                "apos" => Some('\''),
                e if e.starts_with("#x") || e.starts_with("#X") => u32::from_str_radix(&e[2..], 16).ok().and_then(char::from_u32),
                e if e.starts_with('#') => e[1..].parse().ok().and_then(char::from_u32),
                _ => None,
            };
            match rep {
                Some(r) => out.push(r),
                None => {
                    out.push('&');
                    out.push_str(&ent);
                    if semi {
                        out.push(';');
                    }
                }
            }
        } else if c == '\r' || c == '\n' {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    // Collapse runs of spaces and excess blank lines.
    let mut result = String::with_capacity(out.len());
    let mut blank_lines = 0;
    for line in out.lines() {
        let l = line.split(' ').filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
        if l.trim().is_empty() {
            blank_lines += 1;
            if blank_lines > 1 {
                continue;
            }
        } else {
            blank_lines = 0;
        }
        result.push_str(l.trim_end());
        result.push_str("\r\n");
    }
    result.trim().to_string()
}

struct Walker {
    body: Option<String>,
    html: Option<(Vec<u8>, i32)>,
    attachments: Vec<Attachment>,
}

impl Walker {
    fn add_attachment(&mut self, part: &ParsedMail, mime: &str, filename: Option<String>) {
        let data = part.get_body_raw().unwrap_or_default();
        let ext = extension_for(mime);
        let mut name = filename.map(|f| crate::names::nfc(&sanitize_filename(&decode_words(&f)))).unwrap_or_default();
        if name.is_empty() && mime == "message/rfc822" {
            // Name embedded messages after their subject.
            if let Ok(inner) = mailparse::parse_headers(&data) {
                if let Some(s) = inner.0.get_first_value("Subject") {
                    name = sanitize_filename(&s).chars().take(80).collect();
                    if !name.is_empty() {
                        name.push_str(".eml");
                    }
                }
            }
        }
        if name.is_empty() {
            name = format!("attachment{}.{}", self.attachments.len() + 1, ext);
        }
        let content_id = part
            .headers
            .get_first_value("Content-ID")
            .map(|c| c.trim().trim_start_matches('<').trim_end_matches('>').to_string())
            .filter(|c| !c.is_empty());
        self.attachments.push(Attachment { filename: name, mime_type: mime.to_string(), data, content_id });
    }

    fn walk(&mut self, part: &ParsedMail, depth: usize) {
        let mime = part.ctype.mimetype.to_ascii_lowercase();
        if mime.starts_with("multipart/") && !part.subparts.is_empty() && depth < 64 {
            for sub in &part.subparts {
                self.walk(sub, depth + 1);
            }
            return;
        }
        let disp = part.get_content_disposition();
        let filename = disp.params.get("filename").or_else(|| part.ctype.params.get("name")).cloned();
        let is_attachment = matches!(disp.disposition, DispositionType::Attachment) || filename.is_some();
        if !is_attachment && mime == "text/plain" {
            let text = part.get_body().unwrap_or_default();
            match &mut self.body {
                None => self.body = Some(text),
                Some(b) => {
                    b.push_str("\r\n\r\n");
                    b.push_str(&text);
                }
            }
            return;
        }
        if !is_attachment && mime == "text/html" && self.html.is_none() {
            let cs = part.ctype.charset.to_ascii_lowercase();
            let cp = charset_codepage(&cs);
            self.html = Some(match cp {
                // Keep the original bytes so any <meta charset> stays correct.
                Some(cp) if cp != 65001 && cp != 20127 => (part.get_body_raw().unwrap_or_default(), cp),
                _ => (part.get_body().unwrap_or_default().into_bytes(), 65001),
            });
            return;
        }
        self.add_attachment(part, &mime, filename);
    }
}

fn parse_addresses(parsed: &ParsedMail, header: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for h in parsed.headers.get_all_headers(header) {
        match mailparse::addrparse_header(h) {
            Ok(list) => {
                for a in list.iter() {
                    match a {
                        MailAddr::Single(s) => out.push((s.display_name.clone().unwrap_or_default(), s.addr.clone())),
                        MailAddr::Group(g) => {
                            for s in &g.addrs {
                                out.push((s.display_name.clone().unwrap_or_default(), s.addr.clone()));
                            }
                        }
                    }
                }
            }
            Err(_) => {
                let v = h.get_value();
                if !v.trim().is_empty() {
                    out.push((v.trim().to_string(), String::new()));
                }
            }
        }
    }
    out
}

fn strip_brackets(s: Option<String>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

/// Convert one raw message. Never fails: unparseable messages are kept as
/// an .eml attachment so no mail is lost.
pub fn convert(raw: &RawMessage) -> (Message, bool) {
    let status = mozilla_status(&raw.data);
    let headers = header_block(&raw.data);
    let fallback_date = envelope_date(&raw.from_line).unwrap_or_else(|| {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
    });
    let mut m = Message {
        headers: headers.clone(),
        read: status & MOZ_READ != 0,
        flagged: status & MOZ_MARKED != 0,
        importance: 1,
        size: raw.data.len().min(i32::MAX as usize) as u32,
        date: unix_to_filetime(fallback_date),
        ..Default::default()
    };

    let parsed = match mailparse::parse_mail(&raw.data) {
        Ok(p) => p,
        Err(_) => {
            m.subject = "(unreadable message)".into();
            m.body = Some("This message could not be parsed; the original is attached.".into());
            m.attachments.push(Attachment {
                filename: "original.eml".into(),
                mime_type: "message/rfc822".into(),
                data: raw.data.clone(),
                content_id: None,
            });
            return (m, false);
        }
    };
    let h = &parsed.headers;
    m.subject = h.get_first_value("Subject").unwrap_or_default().replace(['\r', '\n'], "");
    if let Some(d) = h.get_first_value("Date") {
        if let Ok(t) = mailparse::dateparse(&d) {
            m.date = unix_to_filetime(t);
        }
    }
    if let Some((name, email)) = parse_addresses(&parsed, "From").into_iter().next() {
        m.from_name = name;
        m.from_email = email;
    }
    for (hdr, kind) in [("To", RECIP_TO), ("Cc", RECIP_CC), ("Bcc", RECIP_BCC)] {
        for (name, email) in parse_addresses(&parsed, hdr) {
            m.recipients.push(Recipient { name, email, kind });
        }
    }
    m.message_id = strip_brackets(h.get_first_value("Message-ID"));
    m.in_reply_to = strip_brackets(h.get_first_value("In-Reply-To"));
    m.references = strip_brackets(h.get_first_value("References"));

    let prio = h.get_first_value("X-Priority").unwrap_or_default();
    let imp = h.get_first_value("Importance").unwrap_or_default().to_ascii_lowercase();
    if prio.trim_start().starts_with(['1', '2']) || imp.contains("high") {
        m.importance = 2;
    } else if prio.trim_start().starts_with(['4', '5']) || imp.contains("low") {
        m.importance = 0;
    }

    let mut w = Walker { body: None, html: None, attachments: Vec::new() };
    w.walk(&parsed, 0);
    if w.body.is_none() {
        if let Some((bytes, cp)) = &w.html {
            let text = if *cp == 65001 {
                String::from_utf8_lossy(bytes).into_owned()
            } else {
                // Re-decode via mailparse for the text version.
                let mut s = String::new();
                fn find_html(p: &ParsedMail, s: &mut String) {
                    if s.is_empty() && p.ctype.mimetype.eq_ignore_ascii_case("text/html") {
                        *s = p.get_body().unwrap_or_default();
                    }
                    for sp in &p.subparts {
                        find_html(sp, s);
                    }
                }
                find_html(&parsed, &mut s);
                s
            };
            w.body = Some(html_to_text(&text));
        }
    }
    m.body = w.body;
    m.html = w.html;
    m.attachments = w.attachments;
    (m, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_dates() {
        assert_eq!(envelope_date("From - Thu Jan  1 00:00:00 1970"), Some(0));
        assert_eq!(envelope_date("From - Tue Jan 02 03:04:05 2024"), Some(1704164645));
    }

    #[test]
    fn html_text() {
        assert_eq!(html_to_text("<p>Hello&nbsp;<b>World</b></p><style>x{}</style>"), "Hello World");
    }
}
