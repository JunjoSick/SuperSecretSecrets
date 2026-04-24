# SuperSecretSecrets

> Turn a secret into QR codes even quantum computers can't read.

A client-side web app that encrypts text with **post-quantum cryptography**
(ML-KEM / FIPS 203) and splits the key across multiple QR codes using
**Shamir's Secret Sharing**. Any T-of-N shares can reconstruct the secret;
fewer than T reveal nothing.

Everything runs in your browser. No server, no accounts, no telemetry.

## Features

- **Post-quantum** ML-KEM-512 / 768 / 1024 via
  [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum)
- **Shamir's Secret Sharing** over GF(2⁸), implemented in-tree
- **AES-256-GCM** or **ChaCha20-Poly1305** for payload encryption
- **HKDF-SHA-256** (or SHA3-256) for key derivation
- Optional **Argon2id** passphrase layer
- v2 API support for custodian metadata, weighted/tree policies, vault blobs,
  and opt-in drand quicknet time-locked shares
- Encode and decode in-browser: upload images or scan with a camera
- Safe-by-default (3-of-5, ML-KEM-768, AES-256-GCM); fully configurable

## Dev

```bash
npm install
npm run dev        # start the dev server
npm test           # run the test suite
npm run build      # type-check + production build
```

## Layout

```
src/
├── crypto/        # pq, aead, kdf, shamir, codec, high-level encode/decode
├── qr/            # QR generation (qrcode) + scanning (jsqr)
├── pages/         # Landing, Encode, Recover, About
├── components/    # QrCard, QrScanner, SettingsPanel
└── lib/           # zip download, misc
tests/             # crypto, codec, shamir, and QR-roundtrip tests
```

## Threat model

See the in-app [About](./src/pages/About.tsx) page. TL;DR: this protects
against future quantum adversaries harvesting your encrypted QRs today, and
against any T-1 trustees cooperating. It does not protect against a
compromised device at encode or decode time.

Time-locked shares are an opt-in v2 API feature. They are not post-quantum,
depend on drand quicknet threshold honesty, and require network access or
imported beacon data at unlock time. Vault QR/header material unlocks an
existing `.ssssvault` blob; losing every copy of that blob loses the vault
contents.

## License

Unlicense / public domain. See [LICENSE](./LICENSE).
