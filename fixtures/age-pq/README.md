# age post-quantum test vectors

The upstream age test vectors for the `mlkem768x25519` recipient stanza
(`age1pq1...` recipients), used by the tests in
`crates/pass-ffi/src/age_pq.rs`.

Source: `age/testdata` in https://github.com/C2SP/CCTV at commit
`b88c4b206254ac543df240097e0f1fcc6a664821`: every file named `hybrid*`,
plus `armor_hybrid`. The CCTV age vectors are offered under 0BSD, CC0 1.0
or the Unlicense, at the user's choice.

Each file is a short header, a blank line, then an age file. `expect` is
`success`, `no match` or `header failure`. For `success`, `payload` is the
SHA-256 of the decrypted contents.

One change from upstream: the two vectors stored zlib-compressed there
(`armor_hybrid` and `hybrid_multiple_recipients`) are stored uncompressed
here, with the `compressed: zlib` header line removed, so the tests need
no extra dependency. The age files inside are byte-for-byte the same.

`tagpq-recipient.txt` is not a CCTV vector: it is the `age1tagpq1...`
test recipient from the Rust `age` crate (0.12.1,
`src/native/tagpq.rs`, MIT or Apache-2.0), used to check that a
hardware-held post-quantum key can sit in a post-quantum store.

The matching store fixture is `fixtures/passage/post-quantum`, written by
age itself through passage; see `fixtures/gen-age-pq-store.sh`.
