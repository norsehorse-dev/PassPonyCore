//! Dev dump tool — the P0 gate artifact. Prints what the reference CLIs
//! print, from pass-core's read path:
//!
//!   passpony-dump ls   --format pass|passage --store DIR
//!   passpony-dump show --format pass|passage --store DIR [--identities FILE] ENTRY
//!   passpony-dump entries --format pass|passage --store DIR   (index incl. hidden)
//!
//! For pass stores, decryption honors GNUPGHOME from the environment.

use std::path::PathBuf;
use std::process::ExitCode;

use pass_core::store::{render_ls, Store, StoreFormat};
use pass_devtools::{AgeCliBackend, GpgCliBackend};

fn die(msg: &str) -> ExitCode {
    eprintln!("Error: {msg}");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut cmd = None;
    let mut format = None;
    let mut store_dir = None;
    let mut identities = None;
    let mut entry = None;

    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "ls" | "show" | "entries" if cmd.is_none() => cmd = Some(a),
            "--format" => format = it.next(),
            "--store" => store_dir = it.next().map(PathBuf::from),
            "--identities" => identities = it.next().map(PathBuf::from),
            _ if entry.is_none() => entry = Some(a),
            other => return die(&format!("unexpected argument: {other}")),
        }
    }

    let format = match format.as_deref() {
        Some("pass") => StoreFormat::Pass,
        Some("passage") => StoreFormat::Passage,
        _ => return die("--format pass|passage is required"),
    };
    let Some(store_dir) = store_dir else {
        return die("--store DIR is required");
    };
    let store = match Store::open(store_dir, format) {
        Ok(s) => s,
        Err(e) => return die(&e.to_string()),
    };

    match cmd.as_deref() {
        Some("ls") => match render_ls(&store) {
            Ok(text) => {
                print!("{text}");
                ExitCode::SUCCESS
            }
            Err(e) => die(&e.to_string()),
        },
        Some("entries") => match store.entries() {
            Ok(entries) => {
                for e in entries {
                    println!("{}{}", e.name, if e.hidden { "\t[hidden]" } else { "" });
                }
                ExitCode::SUCCESS
            }
            Err(e) => die(&e.to_string()),
        },
        Some("show") => {
            let Some(entry) = entry else {
                return die("show requires an entry name");
            };
            let result = match format {
                StoreFormat::Passage => {
                    let Some(identities_file) = identities else {
                        return die("--identities FILE is required for passage");
                    };
                    let backend = AgeCliBackend {
                        identities_file,
                        recipients_file: None,
                    };
                    store.read_entry(&entry, &backend)
                }
                StoreFormat::Pass => {
                    let backend = GpgCliBackend {
                        gnupghome: std::env::var_os("GNUPGHOME").map(PathBuf::from),
                    };
                    store.read_entry(&entry, &backend)
                }
            };
            match result {
                Ok(e) => {
                    use std::io::Write;
                    std::io::stdout()
                        .write_all(e.to_bytes())
                        .expect("stdout write");
                    ExitCode::SUCCESS
                }
                Err(e) => die(&e.to_string()),
            }
        }
        _ => die("usage: passpony-dump <ls|show|entries> --format pass|passage --store DIR [--identities FILE] [ENTRY]"),
    }
}
