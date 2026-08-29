//! Password generator: the spec, the alphabet it produces, and uniform
//! sampling from OS entropy. One implementation for the phones and the
//! desktop, so the same settings give the same alphabet everywhere and the
//! sampling rules are tested once.
//!
//! The untouched default is pass's own `generate`: 25 characters drawn from
//! letters, digits, and the 32 printable ASCII punctuation characters (the
//! `[:alnum:][:punct:]` set the CLI feeds to tr). `SymbolSet::None` is the
//! CLI's `--no-symbols`; `SymbolSet::Basic` is the subset most sign-up forms
//! accept without complaint, for the sites that reject the rest.

/// Which punctuation, if any, goes into the alphabet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolSet {
    /// Letters and digits only (`pass generate --no-symbols`).
    None,
    /// [`SYMBOLS_BASIC`]: the punctuation forms rarely reject.
    Basic,
    /// [`SYMBOLS_FULL`]: all 32 printable ASCII punctuation characters, the
    /// pass default.
    Full,
}

/// Everything the generator needs to know. `length` counts characters;
/// every enabled class is guaranteed to appear at least once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GeneratorSpec {
    pub length: u32,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: SymbolSet,
}

#[derive(Debug, thiserror::Error)]
pub enum GenerateError {
    #[error("length must be between {MIN_LENGTH} and {MAX_LENGTH}")]
    BadLength,
    #[error("at least one character class must be enabled")]
    NoClasses,
    #[error("no entropy source: {0}")]
    Entropy(String),
}

pub const MIN_LENGTH: u32 = 8;
pub const MAX_LENGTH: u32 = 128;
/// pass's default length.
pub const DEFAULT_LENGTH: u32 = 25;

pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
/// All 32 printable ASCII punctuation characters, in ASCII order.
pub const SYMBOLS_FULL: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
/// The portal-safe subset: no quotes, backslash, slash, angle brackets,
/// brackets, braces, pipe, caret, tilde, backtick, colon, or semicolon,
/// which are the characters that break forms or get rejected as injection
/// risks. Order matches ASCII order within the subset.
pub const SYMBOLS_BASIC: &str = "!#$%&()*+,-.=?@_";

impl GeneratorSpec {
    /// pass's `generate` defaults: 25 characters, every class, full symbols.
    pub fn pass_default() -> Self {
        GeneratorSpec {
            length: DEFAULT_LENGTH,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: SymbolSet::Full,
        }
    }

    pub fn validate(&self) -> Result<(), GenerateError> {
        if !(MIN_LENGTH..=MAX_LENGTH).contains(&self.length) {
            return Err(GenerateError::BadLength);
        }
        if self.classes().is_empty() {
            return Err(GenerateError::NoClasses);
        }
        Ok(())
    }

    /// Enabled classes in the fixed alphabet order: lowercase, uppercase,
    /// digits, symbols. Same order as the Kotlin constant this replaces.
    fn classes(&self) -> Vec<&'static str> {
        let mut out = Vec::with_capacity(4);
        if self.lowercase {
            out.push(LOWERCASE);
        }
        if self.uppercase {
            out.push(UPPERCASE);
        }
        if self.digits {
            out.push(DIGITS);
        }
        match self.symbols {
            SymbolSet::None => {}
            SymbolSet::Basic => out.push(SYMBOLS_BASIC),
            SymbolSet::Full => out.push(SYMBOLS_FULL),
        }
        out
    }
}

/// The alphabet a spec draws from, for previews and for tests that pin it.
pub fn charset(spec: &GeneratorSpec) -> Result<String, GenerateError> {
    spec.validate()?;
    Ok(spec.classes().concat())
}

/// Generate a password from OS entropy. Each position is an independent
/// uniform draw from the alphabet; a draw missing one of the enabled classes
/// is discarded and redone, so "at least one digit" style rules never bounce
/// the result. With `MIN_LENGTH` and at most four classes that costs a
/// handful of extra draws at worst.
pub fn generate(spec: &GeneratorSpec) -> Result<String, GenerateError> {
    spec.validate()?;
    let classes = spec.classes();
    let alphabet: Vec<u8> = classes.concat().into_bytes();
    let n = u32::try_from(alphabet.len()).expect("alphabet is tiny");
    loop {
        let mut out = Vec::with_capacity(spec.length as usize);
        for _ in 0..spec.length {
            out.push(alphabet[uniform_index(n)? as usize]);
        }
        if classes
            .iter()
            .all(|class| out.iter().any(|b| class.as_bytes().contains(b)))
        {
            // The alphabet is ASCII, so this cannot fail.
            return String::from_utf8(out).map_err(|e| GenerateError::Entropy(e.to_string()));
        }
    }
}

/// Uniform index in `0..n` from OS entropy by rejection: a 32-bit draw is
/// kept only when it falls below the largest multiple of `n` that fits, so
/// no residue class is favored (the modulo bias a plain `% n` would have).
fn uniform_index(n: u32) -> Result<u32, GenerateError> {
    let limit = u32::MAX - (u32::MAX % n);
    loop {
        let mut buf = [0u8; 4];
        getrandom::fill(&mut buf).map_err(|e| GenerateError::Entropy(e.to_string()))?;
        let v = u32::from_le_bytes(buf);
        if v < limit {
            return Ok(v % n);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The alphabet PassPonyAndroid's PasswordGenerator.CHARSET and iOS's
    /// AddEntryView.generate() used before 1.1, character for character.
    const LEGACY_CHARSET: &str =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

    #[test]
    fn pass_default_alphabet_is_the_legacy_one() {
        assert_eq!(
            charset(&GeneratorSpec::pass_default()).unwrap(),
            LEGACY_CHARSET
        );
        assert_eq!(LEGACY_CHARSET.len(), 94);
        assert_eq!(SYMBOLS_FULL.len(), 32);
    }

    #[test]
    fn basic_symbols_are_pinned() {
        assert_eq!(SYMBOLS_BASIC, "!#$%&()*+,-.=?@_");
        assert_eq!(SYMBOLS_BASIC.len(), 16);
        for c in SYMBOLS_BASIC.chars() {
            assert!(SYMBOLS_FULL.contains(c), "{c} is not ASCII punctuation");
        }
        let mut sorted: Vec<char> = SYMBOLS_BASIC.chars().collect();
        sorted.sort_unstable();
        assert_eq!(sorted.into_iter().collect::<String>(), SYMBOLS_BASIC);
    }

    #[test]
    fn charset_follows_class_order() {
        let spec = GeneratorSpec {
            length: 12,
            lowercase: false,
            uppercase: true,
            digits: true,
            symbols: SymbolSet::Basic,
        };
        assert_eq!(
            charset(&spec).unwrap(),
            format!("{UPPERCASE}{DIGITS}{SYMBOLS_BASIC}")
        );
        let spec = GeneratorSpec {
            symbols: SymbolSet::None,
            ..GeneratorSpec::pass_default()
        };
        assert_eq!(
            charset(&spec).unwrap(),
            format!("{LOWERCASE}{UPPERCASE}{DIGITS}")
        );
    }

    #[test]
    fn validation() {
        assert!(matches!(
            charset(&GeneratorSpec {
                length: 7,
                ..GeneratorSpec::pass_default()
            }),
            Err(GenerateError::BadLength)
        ));
        assert!(matches!(
            charset(&GeneratorSpec {
                length: 129,
                ..GeneratorSpec::pass_default()
            }),
            Err(GenerateError::BadLength)
        ));
        assert!(matches!(
            charset(&GeneratorSpec {
                length: 20,
                lowercase: false,
                uppercase: false,
                digits: false,
                symbols: SymbolSet::None,
            }),
            Err(GenerateError::NoClasses)
        ));
        assert!(charset(&GeneratorSpec {
            length: MIN_LENGTH,
            ..GeneratorSpec::pass_default()
        })
        .is_ok());
        assert!(charset(&GeneratorSpec {
            length: MAX_LENGTH,
            ..GeneratorSpec::pass_default()
        })
        .is_ok());
    }

    #[test]
    fn every_enabled_class_is_present() {
        let specs = [
            GeneratorSpec::pass_default(),
            GeneratorSpec {
                length: 8,
                ..GeneratorSpec::pass_default()
            },
            GeneratorSpec {
                length: 19,
                symbols: SymbolSet::Basic,
                ..GeneratorSpec::pass_default()
            },
            GeneratorSpec {
                length: 8,
                lowercase: false,
                uppercase: false,
                digits: true,
                symbols: SymbolSet::None,
            },
        ];
        for spec in specs {
            let alphabet = charset(&spec).unwrap();
            for _ in 0..2_000 {
                let pw = generate(&spec).unwrap();
                assert_eq!(pw.chars().count(), spec.length as usize);
                assert!(pw.chars().all(|c| alphabet.contains(c)), "{pw}");
                if spec.lowercase {
                    assert!(pw.chars().any(|c| LOWERCASE.contains(c)), "{pw}");
                }
                if spec.uppercase {
                    assert!(pw.chars().any(|c| UPPERCASE.contains(c)), "{pw}");
                }
                if spec.digits {
                    assert!(pw.chars().any(|c| DIGITS.contains(c)), "{pw}");
                }
                match spec.symbols {
                    SymbolSet::None => {}
                    SymbolSet::Basic => {
                        assert!(pw.chars().any(|c| SYMBOLS_BASIC.contains(c)), "{pw}")
                    }
                    SymbolSet::Full => {
                        assert!(pw.chars().any(|c| SYMBOLS_FULL.contains(c)), "{pw}")
                    }
                }
            }
        }
    }

    #[test]
    fn the_portal_case() {
        // Issue #5: 8 to 19 characters, basic punctuation only.
        let spec = GeneratorSpec {
            length: 19,
            symbols: SymbolSet::Basic,
            ..GeneratorSpec::pass_default()
        };
        for _ in 0..1_000 {
            let pw = generate(&spec).unwrap();
            assert_eq!(pw.len(), 19);
            assert!(
                pw.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || SYMBOLS_BASIC.as_bytes().contains(&b)),
                "{pw}"
            );
        }
    }

    #[test]
    fn draws_are_not_constant() {
        // A weak sanity check on the entropy path: 20 draws of 25 characters
        // never repeat.
        let spec = GeneratorSpec::pass_default();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            assert!(seen.insert(generate(&spec).unwrap()));
        }
    }

    #[test]
    fn uniform_index_stays_in_range() {
        for n in [1u32, 2, 3, 7, 62, 78, 94] {
            for _ in 0..500 {
                assert!(uniform_index(n).unwrap() < n);
            }
        }
    }
}
