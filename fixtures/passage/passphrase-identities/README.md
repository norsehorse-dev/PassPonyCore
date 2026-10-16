Fixture 6 of docs/passage-store-semantics.md: an age `-p` encrypted
identities file with a root `.age-recipients` carrying the public key, so
only decryption needs the passphrase. The passphrase is `correct horse pony`.
The key is a throwaway generated for this fixture and protects nothing.

- `identities`: armored (`age -p -a`, what the passage README setup writes).
- `identities.binary`: the same file without armor (`age -p`, binary).
- `identities.plain`: the plaintext inside, for comparison.
- `identities.multi`, `identities.multi.plain`: armored file holding a comment and two throwaway identities, like a gopass identities file with more than one key.
- `store/alpha.age`, `goldens/alpha.plain`: one entry encrypted to the key.

    age-keygen -o identities.plain
    age -p -a -o identities identities.plain
    age -p -o identities.binary identities.plain
    age -r "$(cat store/.age-recipients)" -o store/alpha.age goldens/alpha.plain
    age-keygen -o a.txt; age-keygen -o b.txt
    (echo '# gopass-style identities file with two identities'; cat a.txt; echo; cat b.txt) > identities.multi.plain
    age -p -a -o identities.multi identities.multi.plain
