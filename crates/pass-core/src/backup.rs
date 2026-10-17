//! The `.passpony` backup bundle: container format and recovery codes.
//!
//! A `.passpony` file is an ordinary age v1 file with a single scrypt
//! (passphrase) recipient. Its plaintext is the container defined here. The
//! encryption is done by each platform's age engine (the `age-engine`
//! feature on Android, AgePonyCore on iOS, the age crate on desktop), which
//! keeps pass-core crypto-free and means any age implementation can open a
//! backup: `age -d backup.passpony` with the recovery code shows the
//! container. The full wire format is in `docs/BACKUP.md`.
//!
//! The passphrase is always a generated recovery code, never something the
//! user makes up: 29 random Crockford base32 characters plus one check
//! character, shown in six groups of five. The app makes the user type it
//! back before the backup counts as done, and the check character catches a
//! mistyped code at restore time before any scrypt work starts.

/// First line of every container. The number is the format version.
pub const HEADER: &str = "PassPony backup 1";
const TRAILER: &str = "end";

/// Section kinds this version writes. Readers keep sections of other kinds
/// as `Unknown` so a newer backup still restores what this version knows.
pub const KIND_AGE_IDENTITIES: &str = "age-identities";
pub const KIND_PGP_SECRET_KEY: &str = "pgp-secret-key";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BackupError {
    #[error("not a PassPony backup")]
    NotABackup,
    #[error("backup was made by a newer version of PassPony")]
    NewerVersion,
    #[error("backup is truncated or damaged")]
    Damaged,
    #[error("recovery code has the wrong length")]
    CodeLength,
    #[error("recovery code has a character that is not used in codes")]
    CodeCharacter,
    #[error("recovery code has a typo")]
    CodeChecksum,
}

/// One piece of key material. `name` is the file name it came from (PGP
/// keys) and may be empty; it never contains a newline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub kind: String,
    pub name: String,
    pub data: Vec<u8>,
}

/// Serialize sections into the container plaintext.
pub fn encode(sections: &[Section]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(HEADER.as_bytes());
    out.push(b'\n');
    for s in sections {
        let kind: String = s.kind.chars().filter(|c| !c.is_whitespace()).collect();
        let name = s.name.replace(['\n', '\r'], " ");
        let line = if name.is_empty() {
            format!("{kind} {}\n", s.data.len())
        } else {
            format!("{kind} {} {name}\n", s.data.len())
        };
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(&s.data);
        out.push(b'\n');
    }
    out.extend_from_slice(TRAILER.as_bytes());
    out.push(b'\n');
    out
}

/// Parse container plaintext. Every section is returned, known kinds and
/// unknown ones alike; a missing trailer or a length that runs past the end
/// is `Damaged`, never a partial result.
pub fn decode(data: &[u8]) -> Result<Vec<Section>, BackupError> {
    let mut pos = 0usize;
    let header = read_line(data, &mut pos).ok_or(BackupError::NotABackup)?;
    let version = header
        .strip_prefix("PassPony backup ")
        .ok_or(BackupError::NotABackup)?;
    match version.trim().parse::<u32>() {
        Ok(1) => {}
        Ok(v) if v > 1 => return Err(BackupError::NewerVersion),
        _ => return Err(BackupError::NotABackup),
    }
    let mut sections = Vec::new();
    loop {
        let line = read_line(data, &mut pos).ok_or(BackupError::Damaged)?;
        if line == TRAILER {
            return if pos == data.len() {
                Ok(sections)
            } else {
                Err(BackupError::Damaged)
            };
        }
        let mut parts = line.splitn(3, ' ');
        let kind = parts
            .next()
            .filter(|k| !k.is_empty())
            .ok_or(BackupError::Damaged)?;
        let len: usize = parts
            .next()
            .and_then(|l| l.parse().ok())
            .ok_or(BackupError::Damaged)?;
        let name = parts.next().unwrap_or("").to_owned();
        let end = pos.checked_add(len).ok_or(BackupError::Damaged)?;
        let body = data.get(pos..end).ok_or(BackupError::Damaged)?.to_vec();
        if data.get(end) != Some(&b'\n') {
            return Err(BackupError::Damaged);
        }
        pos = end + 1;
        sections.push(Section {
            kind: kind.to_owned(),
            name,
            data: body,
        });
    }
}

fn read_line<'a>(data: &'a [u8], pos: &mut usize) -> Option<&'a str> {
    let rest = data.get(*pos..)?;
    let nl = rest.iter().position(|&b| b == b'\n')?;
    let line = std::str::from_utf8(&rest[..nl]).ok()?;
    *pos += nl + 1;
    Some(line)
}

// --- recovery codes -----------------------------------------------------------

/// Crockford base32: digits and capitals without I, L, O, U.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const CODE_CHARS: usize = 30;
const GROUP: usize = 5;

/// A fresh recovery code, canonical form `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
/// 29 random characters (145 bits) and a check character.
pub fn generate_recovery_code() -> Result<String, getrandom::Error> {
    let mut random = [0u8; CODE_CHARS - 1];
    getrandom::fill(&mut random)?;
    let mut values: Vec<u8> = random.iter().map(|b| b & 31).collect();
    values.push(check_value(&values));
    random.fill(0);
    Ok(format_code(&values))
}

/// Canonicalize what the user typed: case, spaces, and dashes are ignored,
/// and the look-alikes O, I, and L read as 0, 1, and 1. The result is the
/// exact passphrase the backup was encrypted with.
pub fn normalize_recovery_code(input: &str) -> Result<String, BackupError> {
    let mut values = Vec::with_capacity(CODE_CHARS);
    for c in input.chars() {
        if c.is_whitespace() || c == '-' {
            continue;
        }
        let c = match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        let v = CROCKFORD
            .iter()
            .position(|&a| a as char == c)
            .ok_or(BackupError::CodeCharacter)?;
        values.push(v as u8);
    }
    if values.len() != CODE_CHARS {
        return Err(BackupError::CodeLength);
    }
    let (body, check) = values.split_at(CODE_CHARS - 1);
    if check_value(body) != check[0] {
        return Err(BackupError::CodeChecksum);
    }
    Ok(format_code(&values))
}

/// Luhn mod 32 over the code values: catches every single-character typo
/// and most swaps of neighbors.
fn check_value(values: &[u8]) -> u8 {
    let n = 32u32;
    let mut factor = 2u32;
    let mut sum = 0u32;
    for &v in values.iter().rev() {
        let addend = factor * u32::from(v);
        sum += addend / n + addend % n;
        factor = if factor == 2 { 1 } else { 2 };
    }
    ((n - sum % n) % n) as u8
}

fn format_code(values: &[u8]) -> String {
    values
        .chunks(GROUP)
        .map(|g| {
            g.iter()
                .map(|&v| CROCKFORD[v as usize] as char)
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<Section> {
        vec![
            Section {
                kind: KIND_AGE_IDENTITIES.into(),
                name: String::new(),
                data: b"# public key: age1x\nAGE-SECRET-KEY-1X\n".to_vec(),
            },
            Section {
                kind: KIND_PGP_SECRET_KEY.into(),
                name: "work key.asc".into(),
                data: vec![0, 10, 255, b'\n', b'e', b'n', b'd', b'\n'],
            },
        ]
    }

    #[test]
    fn round_trip_including_binary_and_lookalike_bytes() {
        let bytes = encode(&sample());
        assert!(bytes.starts_with(b"PassPony backup 1\nage-identities 38\n"));
        assert!(bytes.ends_with(b"\nend\n"));
        assert_eq!(decode(&bytes).unwrap(), sample());
        assert_eq!(decode(&encode(&[])).unwrap(), vec![]);
    }

    #[test]
    fn unknown_kinds_survive_and_damage_is_caught() {
        let mut s = sample();
        s.push(Section {
            kind: "ssh-private-key".into(),
            name: "id_ed25519".into(),
            data: b"key".to_vec(),
        });
        assert_eq!(decode(&encode(&s)).unwrap()[2].kind, "ssh-private-key");

        let bytes = encode(&sample());
        assert_eq!(decode(&bytes[..bytes.len() - 4]), Err(BackupError::Damaged));
        assert_eq!(
            decode(&bytes[..bytes.len() - 20]),
            Err(BackupError::Damaged)
        );
        let mut extra = bytes.clone();
        extra.extend_from_slice(b"junk");
        assert_eq!(decode(&extra), Err(BackupError::Damaged));
        assert_eq!(decode(b"hello\n"), Err(BackupError::NotABackup));
        assert_eq!(
            decode(b"PassPony backup 2\nend\n"),
            Err(BackupError::NewerVersion)
        );
    }

    #[test]
    fn recovery_codes_normalize_and_check() {
        let code = generate_recovery_code().unwrap();
        assert_eq!(code.len(), 35);
        assert_eq!(code.matches('-').count(), 5);
        assert_eq!(normalize_recovery_code(&code).unwrap(), code);
        let sloppy = code
            .to_lowercase()
            .replace('-', " ")
            .replace('0', "o")
            .replace('1', "l");
        assert_eq!(normalize_recovery_code(&sloppy).unwrap(), code);

        // Every single-character substitution is caught.
        let plain: Vec<char> = code.chars().filter(|&c| c != '-').collect();
        for i in 0..plain.len() {
            for &alt in CROCKFORD.iter() {
                let alt = alt as char;
                if alt == plain[i] {
                    continue;
                }
                let mut typo = plain.clone();
                typo[i] = alt;
                let typo: String = typo.into_iter().collect();
                assert_eq!(
                    normalize_recovery_code(&typo),
                    Err(BackupError::CodeChecksum)
                );
            }
        }
        assert_eq!(normalize_recovery_code("ABC"), Err(BackupError::CodeLength));
        assert_eq!(
            normalize_recovery_code(&code.replace(plain[0], "U")),
            Err(BackupError::CodeCharacter)
        );
        assert_ne!(generate_recovery_code().unwrap(), code);
    }
}
