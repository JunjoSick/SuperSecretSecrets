export default function About() {
  return (
    <div className="mx-auto max-w-4xl px-6 pb-24 pt-12">
      <div className="mono-upper">threat model</div>
      <h1 className="mt-2 text-3xl font-medium tracking-tight text-ink-50">About &amp; threat model</h1>
      <p className="mt-3 border-l border-accent-300/40 pl-4 text-ink-300">
        SuperSecretSecrets is a client-side tool for turning a piece of text
        into a set of QR codes that can be distributed to trustees for
        long-term backup. Any threshold-many trustees can cooperate to recover
        the original text; fewer than threshold-many learn nothing.
      </p>

      <h2 className="mt-10 text-xl font-medium text-ink-50">How it works</h2>
      <ol className="mt-3 list-decimal space-y-2 pl-5 text-ink-300">
        <li>
          A random 64-byte seed is generated in your browser and used to
          derive an ML-KEM keypair (FIPS 203).
        </li>
        <li>
          The text is encrypted with AES-256-GCM under a key derived via HKDF
          from an ML-KEM-encapsulated shared secret.
        </li>
        <li>
          The seed is split into N Shamir shares with threshold T (default
          3-of-5). Each share becomes a QR code.
        </li>
        <li>
          One additional "header" QR carries the ciphertext, KEM encapsulation,
          and algorithm parameters (and is split into multiple codes for
          long texts).
        </li>
        <li>
          To recover, scan all header chunks and any T share QRs. The app
          reconstructs the seed, re-derives the keypair, decapsulates, and
          decrypts.
        </li>
      </ol>

      <h2 className="mt-10 text-xl font-medium text-ink-50">What this protects against</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-300">
        <li>
          <strong className="text-ink-100">Future quantum adversaries.</strong>{' '}
          ML-KEM is believed secure against quantum attack. AES-256 retains a
          128-bit post-quantum security margin against Grover's algorithm.
          Shamir's Secret Sharing is information-theoretically secure below
          the threshold.
        </li>
        <li>
          <strong className="text-ink-100">Loss of one or two trustees.</strong>{' '}
          With 3-of-5, you can lose up to 2 shares and still recover.
        </li>
        <li>
          <strong className="text-ink-100">Tampering.</strong> AEAD tags detect
          any modification to the ciphertext.
        </li>
      </ul>

      <h2 className="mt-10 text-xl font-medium text-ink-50">What it does NOT protect against</h2>
      <ul className="mt-3 list-disc space-y-2 pl-5 text-ink-300">
        <li>A compromised browser or device at the time of encoding/decoding.</li>
        <li>
          Trustees colluding beyond the threshold. Choose threshold-N pairs
          intentionally.
        </li>
        <li>Losing more than (N − T) shares — that makes the secret unrecoverable.</li>
        <li>Bad passphrases. If you enable the passphrase option, use a strong one.</li>
      </ul>

      <h2 className="mt-10 text-xl font-medium text-ink-50">Cryptographic defaults</h2>
      <dl className="card mt-3 grid grid-cols-1 gap-x-6 gap-y-2 p-5 text-sm sm:grid-cols-[12rem_1fr]">
        <Dt>KEM</Dt><Dd>ML-KEM-768 (FIPS 203)</Dd>
        <Dt>AEAD</Dt><Dd>AES-256-GCM</Dd>
        <Dt>KDF</Dt><Dd>HKDF-SHA-256</Dd>
        <Dt>Secret sharing</Dt><Dd>Shamir over GF(2^8) with AES polynomial</Dd>
        <Dt>Default T-of-N</Dt><Dd>3-of-5</Dd>
        <Dt>Passphrase stretching</Dt><Dd>Argon2id (when enabled)</Dd>
      </dl>

      <h2 className="mt-10 text-xl font-medium text-ink-50">Libraries</h2>
      <p className="mt-3 text-ink-300">
        Built on{' '}
        <a className="underline decoration-dotted" href="https://github.com/paulmillr/noble-post-quantum">@noble/post-quantum</a>,{' '}
        <a className="underline decoration-dotted" href="https://github.com/paulmillr/noble-ciphers">@noble/ciphers</a>, and{' '}
        <a className="underline decoration-dotted" href="https://github.com/paulmillr/noble-hashes">@noble/hashes</a>.
        Shamir's Secret Sharing is implemented locally in{' '}
        <code className="font-mono text-ink-200">src/crypto/shamir.ts</code> — under
        100 lines of auditable code.
      </p>
    </div>
  );
}

function Dt({ children }: { children: React.ReactNode }) {
  return <dt className="text-ink-400">{children}</dt>;
}
function Dd({ children }: { children: React.ReactNode }) {
  return <dd className="font-mono text-ink-100">{children}</dd>;
}
