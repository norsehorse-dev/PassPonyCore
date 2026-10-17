Throwaway SSH keys made with `ssh-keygen` for the `ssh` module tests. They
protect nothing. Passphrase for the `-protected` keys: `pony ssh test`.

- `ed25519-protected`: Ed25519, OpenSSH format, passphrase
- `rsa-protected`: RSA 2048, OpenSSH format, passphrase
- `ecdsa-plain`: ECDSA P-256, OpenSSH format, no passphrase
- `rsa-legacy-pem`: RSA in the old PEM format, which import refuses with a
  hint to convert it
