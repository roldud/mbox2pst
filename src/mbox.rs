//! Streaming reader for mbox files as written by Thunderbird.
//!
//! Messages are separated by lines beginning with "From ". Thunderbird
//! escapes body lines that begin with "From " (as ">From "), so a "From "
//! line that follows a blank line, or that looks like a real envelope line,
//! starts a new message.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

pub struct RawMessage {
    /// The "From " envelope line (without line ending), if present.
    pub from_line: String,
    pub data: Vec<u8>,
}

pub struct MboxReader {
    reader: BufReader<File>,
    pending: Option<Vec<u8>>,
    first: bool,
    done: bool,
}

/// Does the file look like an mbox (starts with "From ")?
pub fn looks_like_mbox(path: &Path) -> bool {
    let mut buf = [0u8; 5];
    match File::open(path).and_then(|mut f| f.read_exact(&mut buf)) {
        Ok(()) => &buf == b"From ",
        Err(_) => false,
    }
}

fn is_blank(line: &[u8]) -> bool {
    line == b"\n" || line == b"\r\n"
}

/// Heuristic for "From sender date" envelope lines: must contain a time (hh:mm)
/// and a four-digit year.
fn looks_like_envelope(line: &[u8]) -> bool {
    let s = String::from_utf8_lossy(line);
    let has_time = s.as_bytes().windows(5).any(|w| {
        w[0].is_ascii_digit() && w[1].is_ascii_digit() && w[2] == b':' && w[3].is_ascii_digit() && w[4].is_ascii_digit()
    });
    let has_year = s.split_whitespace().any(|t| t.len() == 4 && t.chars().all(|c| c.is_ascii_digit()));
    has_time && has_year
}

impl MboxReader {
    pub fn open(path: &Path) -> io::Result<Self> {
        Ok(MboxReader { reader: BufReader::with_capacity(1 << 20, File::open(path)?), pending: None, first: true, done: false })
    }

    fn read_line(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut line = Vec::new();
        let n = self.reader.read_until(b'\n', &mut line)?;
        Ok(if n == 0 { None } else { Some(line) })
    }

    fn next_message(&mut self) -> io::Result<Option<RawMessage>> {
        if self.done {
            return Ok(None);
        }
        // Find the envelope line of this message.
        let envelope = match self.pending.take() {
            Some(l) => Some(l),
            None => {
                let mut l = self.read_line()?;
                // Skip leading blank lines.
                while let Some(x) = &l {
                    if is_blank(x) {
                        l = self.read_line()?;
                    } else {
                        break;
                    }
                }
                match l {
                    None => {
                        self.done = true;
                        return Ok(None);
                    }
                    Some(x) if x.starts_with(b"From ") => Some(x),
                    Some(x) => {
                        // Not an mbox envelope: treat the line as message data.
                        self.pending = Some(x);
                        None
                    }
                }
            }
        };
        let first_msg = self.first;
        self.first = false;
        let mut data = Vec::new();
        if envelope.is_none() {
            if let Some(x) = self.pending.take() {
                data.extend_from_slice(&x);
            }
            if !first_msg {
                // Should not happen; avoid looping forever.
                self.done = true;
            }
        }
        let mut prev_blank = false;
        loop {
            let Some(line) = self.read_line()? else {
                self.done = true;
                break;
            };
            if line.starts_with(b"From ") && (prev_blank || looks_like_envelope(&line)) && envelope.is_some() {
                self.pending = Some(line);
                break;
            }
            prev_blank = is_blank(&line);
            data.extend_from_slice(&line);
        }
        // The blank line before the next envelope belongs to the mbox format.
        if data.ends_with(b"\r\n\r\n") {
            data.truncate(data.len() - 2);
        } else if data.ends_with(b"\n\n") {
            data.truncate(data.len() - 1);
        }
        let from_line = envelope
            .map(|e| String::from_utf8_lossy(&e).trim_end_matches(['\r', '\n']).to_string())
            .unwrap_or_default();
        Ok(Some(RawMessage { from_line, data }))
    }
}

impl Iterator for MboxReader {
    type Item = io::Result<RawMessage>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_message().transpose()
    }
}
