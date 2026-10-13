//! mbox2pst: convert a Thunderbird mail directory into an Outlook PST file.

/// println! that ignores a closed stdout (e.g. when piped into `head`).
macro_rules! say {
    ($($t:tt)*) => {{
        use std::io::Write;
        let _ = writeln!(std::io::stdout(), $($t)*);
    }};
}

mod crc;
mod ltp;
mod mbox;
mod mime;
mod names;
mod ndb;
mod pst;

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "\
mbox2pst - convert a Thunderbird mail directory into an Outlook PST file

USAGE:
    mbox2pst [OPTIONS] <INPUT> <OUTPUT.pst>

ARGUMENTS:
    <INPUT>         A Thunderbird mail directory (e.g. a profile's
                    \"Mail/Local Folders\" or \"ImapMail/imap.example.com\"),
                    a directory that contains such directories, or a single
                    mbox file.
    <OUTPUT.pst>    The Unicode PST file to create.

OPTIONS:
    -n, --name <NAME>      Display name of the PST in Outlook
                           (default: \"Thunderbird Import\")
        --include-deleted  Also import messages that Thunderbird marked as
                           deleted but has not yet compacted away
        --keep-trash       Import Thunderbird's \"Trash\" as a normal folder
                           instead of merging it into \"Deleted Items\"
    -f, --force            Overwrite OUTPUT if it already exists
    -q, --quiet            Only print errors and the final summary
    -h, --help             Show this help
    -V, --version          Show version
";

struct Options {
    input: PathBuf,
    output: PathBuf,
    name: String,
    include_deleted: bool,
    keep_trash: bool,
    force: bool,
    quiet: bool,
}

fn parse_args() -> Result<Options, String> {
    let mut args = std::env::args().skip(1);
    let mut positional = Vec::new();
    let mut o = Options {
        input: PathBuf::new(),
        output: PathBuf::new(),
        name: "Thunderbird Import".into(),
        include_deleted: false,
        keep_trash: false,
        force: false,
        quiet: false,
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                std::process::exit(0);
            }
            "-V" | "--version" => {
                say!("mbox2pst {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "-n" | "--name" => o.name = args.next().ok_or("--name needs a value")?,
            "--include-deleted" => o.include_deleted = true,
            "--keep-trash" => o.keep_trash = true,
            "-f" | "--force" => o.force = true,
            "-q" | "--quiet" => o.quiet = true,
            s if s.starts_with("--name=") => o.name = s["--name=".len()..].to_string(),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option '{}'", s)),
            _ => positional.push(PathBuf::from(a)),
        }
    }
    if positional.len() != 2 {
        return Err("expected <INPUT> and <OUTPUT.pst>".into());
    }
    o.output = positional.pop().unwrap();
    o.input = positional.pop().unwrap();
    Ok(o)
}

/// A mail folder discovered on disk.
struct FolderSpec {
    name: String,
    mbox: Option<PathBuf>,
    children: Vec<FolderSpec>,
}

/// Recursively discover Thunderbird folders in `dir`.
///
/// Thunderbird stores folder "X" as an mbox file "X" (plus an "X.msf" index)
/// and its subfolders in a directory "X.sbd". Plain subdirectories that
/// contain mail (e.g. "Local Folders" inside "Mail") become folders too.
///
/// File names are handled as raw bytes (`OsString`) so that names in any
/// encoding (UTF-8, legacy Latin-1, ...) are opened exactly as stored on
/// disk; they are only decoded to produce the folder's display name.
fn scan_dir(dir: &Path, depth: usize) -> Vec<FolderSpec> {
    let Ok(rd) = fs::read_dir(dir) else { return Vec::new() };
    let mut files: BTreeSet<OsString> = BTreeSet::new();
    let mut dirs: BTreeSet<OsString> = BTreeSet::new();
    for e in rd.flatten() {
        let path = e.path();
        if path.is_dir() {
            dirs.insert(e.file_name());
        } else if path.is_file() {
            files.insert(e.file_name());
        }
    }
    let with_suffix = |name: &OsStr, suffix: &str| {
        let mut n = name.to_os_string();
        n.push(suffix);
        n
    };
    let mut out = Vec::new();
    let mut used_dirs = BTreeSet::new();
    for f in &files {
        if f.as_bytes().ends_with(b".msf") {
            continue;
        }
        let path = dir.join(f);
        let empty_folder =
            fs::metadata(&path).map(|m| m.len() == 0).unwrap_or(false) && files.contains(&with_suffix(f, ".msf"));
        if !(empty_folder || mbox::looks_like_mbox(&path)) {
            continue;
        }
        let sbd = with_suffix(f, ".sbd");
        let children = if dirs.contains(&sbd) && depth < 64 {
            used_dirs.insert(sbd.clone());
            scan_dir(&dir.join(&sbd), depth + 1)
        } else {
            Vec::new()
        };
        out.push(FolderSpec { name: names::folder_name(f), mbox: Some(path), children });
    }
    for d in &dirs {
        if used_dirs.contains(d) || depth >= 64 {
            continue;
        }
        let children = scan_dir(&dir.join(d), depth + 1);
        if children.is_empty() {
            continue;
        }
        let bytes = d.as_bytes();
        let stem = OsStr::from_bytes(bytes.strip_suffix(b".sbd").unwrap_or(bytes));
        out.push(FolderSpec { name: names::folder_name(stem), mbox: None, children });
    }
    out
}

#[derive(Default)]
struct Stats {
    folders: usize,
    messages: usize,
    skipped_deleted: usize,
    unparseable: usize,
}

fn import_folder(
    w: &mut pst::PstWriter,
    parent: usize,
    spec: &FolderSpec,
    target: Option<usize>,
    o: &Options,
    stats: &mut Stats,
    path_label: &str,
) -> Result<(), String> {
    let folder = match target {
        Some(t) => t,
        None => w.add_folder(parent, &spec.name),
    };
    stats.folders += 1;
    let label = if path_label.is_empty() { spec.name.clone() } else { format!("{}/{}", path_label, spec.name) };
    if let Some(path) = &spec.mbox {
        let reader = mbox::MboxReader::open(path).map_err(|e| format!("{}: {}", path.display(), e))?;
        let mut count = 0usize;
        for raw in reader {
            let raw = raw.map_err(|e| format!("{}: {}", path.display(), e))?;
            if raw.data.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            if !o.include_deleted && mime::mozilla_status(&raw.data) & mime::MOZ_EXPUNGED != 0 {
                stats.skipped_deleted += 1;
                continue;
            }
            let (msg, ok) = mime::convert(&raw);
            if !ok {
                stats.unparseable += 1;
            }
            w.add_message(folder, &msg).map_err(|e| format!("writing PST: {}", e))?;
            count += 1;
        }
        stats.messages += count;
        if !o.quiet {
            let pad = 50usize.saturating_sub(label.chars().count());
            say!("  {}{} {:>7} messages", label, " ".repeat(pad), count);
        }
    }
    for child in &spec.children {
        import_folder(w, folder, child, None, o, stats, &label)?;
    }
    Ok(())
}

fn convert(o: &Options, specs: &[FolderSpec], stats: &mut Stats) -> Result<u64, String> {
    let mut w = pst::PstWriter::create(&o.output, &o.name).map_err(|e| format!("{}: {}", o.output.display(), e))?;
    for spec in specs {
        let target = if !o.keep_trash && spec.name.eq_ignore_ascii_case("Trash") {
            Some(pst::FOLDER_DELETED_ITEMS)
        } else {
            None
        };
        import_folder(&mut w, pst::FOLDER_TOP, spec, target, o, stats, "")?;
    }
    w.finish().map_err(|e| format!("finalising PST: {}", e))
}

fn run(o: &Options) -> Result<(), String> {
    if !o.input.exists() {
        return Err(format!("input '{}' does not exist", o.input.display()));
    }
    if o.output.exists() && !o.force {
        return Err(format!("output '{}' already exists (use --force to overwrite)", o.output.display()));
    }

    let specs = if o.input.is_file() {
        let name = o.input.file_name().map(names::folder_name).unwrap_or_else(|| "Inbox".into());
        vec![FolderSpec { name, mbox: Some(o.input.clone()), children: Vec::new() }]
    } else {
        scan_dir(&o.input, 0)
    };
    if specs.is_empty() {
        return Err(format!("no Thunderbird mbox folders found in '{}'", o.input.display()));
    }

    if !o.quiet {
        say!("Converting {} -> {}", o.input.display(), o.output.display());
    }
    let mut stats = Stats::default();
    let size = match convert(o, &specs, &mut stats) {
        Ok(s) => s,
        Err(e) => {
            // Don't leave a half-written PST behind.
            let _ = fs::remove_file(&o.output);
            return Err(e);
        }
    };

    say!(
        "Done: {} messages in {} folders written to {} ({:.1} MB)",
        stats.messages,
        stats.folders,
        o.output.display(),
        size as f64 / 1_048_576.0
    );
    if stats.skipped_deleted > 0 {
        say!("Skipped {} messages marked as deleted (use --include-deleted to keep them)", stats.skipped_deleted);
    }
    if stats.unparseable > 0 {
        say!("{} messages could not be parsed and were stored as .eml attachments", stats.unparseable);
    }
    if size > 50 * 1024 * 1024 * 1024 {
        eprintln!("warning: the PST is larger than 50 GB, Outlook's default size limit");
    }
    Ok(())
}

fn main() -> ExitCode {
    let o = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("error: {}\n\n{}", e, USAGE);
            return ExitCode::from(2);
        }
    };
    match run(&o) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {}", e);
            ExitCode::FAILURE
        }
    }
}
