# Security Notes

SuperSecretSecrets keeps the default single-secret flow on the original SSS1
format unless a v2 feature is requested.

## v3 ZK Commitments

v3 commitments are opt-in. They bind the policy manifest, recovered plaintext
or vault root key, vault tree root, and per-share opening proofs into the QR
material so publication-time tampering is detectable.

Security limits:

- The v3 ZK layer is auxiliary integrity, not confidentiality.
- Pedersen/Schnorr proofs use Ristretto255 and are not post-quantum.
- A verified vault disclosure proves one entry belongs to the published
  vault-tree root; the verifier still needs an authentic root to compare.

## v3 VDF-Locked Shares

v3 VDF locks are opt-in and run per share. The encoder derives a public
class-group generator from `bundleId || shareIdx`, seals the share payload under
the VDF output, and publishes a Wesolowski proof for the computed output.

Security limits:

- VDF locks are not post-quantum.
- The delay is a sequential-work estimate, not a guaranteed clock duration.
- Class-group operations are intentionally over public inputs; do not reuse
  this implementation for secret-input class-group protocols without review.
- The browser caches sampled discriminants per session to avoid repeated
  multi-second setup costs.

## v2 Vaults

Vault QR/header material unwraps a stable vault root key. The editable vault
contents live in the exported `.ssssvault` blob, protected by AEAD under that
root key. Losing every copy of the `.ssssvault` blob loses the vault contents;
shares and headers only unlock a blob that still exists.

Image payloads use the same vault path and preserve exact file bytes, name, and
MIME type by default. This keeps disclosure proofs stable, but it also preserves
metadata such as EXIF. The Encode page has an explicit strip-metadata option
that re-encodes the image before vaulting it.

## v2 Time-Locked Shares

Time-locked shares are stable but opt-in. They are never enabled by default.
They use drand quicknet metadata with chain hash
`52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`.

Security limits:

- Time-lock encryption is not post-quantum.
- Unlock depends on drand quicknet threshold honesty.
- Unlock needs network access or imported beacon data for the target round.
- Plaintext share metadata remains visible outside the time lock.
