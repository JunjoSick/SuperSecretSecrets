# Security Notes

SuperSecretSecrets keeps the default single-secret flow on the original SSS1
format unless a v2 feature is requested.

## v2 Vaults

Vault QR/header material unwraps a stable vault root key. The editable vault
contents live in the exported `.ssssvault` blob, protected by AEAD under that
root key. Losing every copy of the `.ssssvault` blob loses the vault contents;
shares and headers only unlock a blob that still exists.

## v2 Time-Locked Shares

Time-locked shares are stable but opt-in. They are never enabled by default.
They use drand quicknet metadata with chain hash
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.

Security limits:

- Time-lock encryption is not post-quantum.
- Unlock depends on drand quicknet threshold honesty.
- Unlock needs network access or imported beacon data for the target round.
- Plaintext share metadata remains visible outside the time lock.
