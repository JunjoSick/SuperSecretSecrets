import type { EncodeOptions } from '../crypto';
import type { EccLevel } from '../qr/generate';

type Props = {
  opts: EncodeOptions;
  setOpts: (o: EncodeOptions) => void;
  ecc: EccLevel;
  setEcc: (e: EccLevel) => void;
};

export function SettingsPanel({ opts, setOpts, ecc, setEcc }: Props) {
  return (
    <details className="card group p-5 open:pb-6">
      <summary className="cursor-pointer select-none list-none">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold text-ink-100">Advanced options</div>
            <div className="text-xs text-ink-400">
              ML-KEM / cipher / KDF / error correction — defaults are safe.
            </div>
          </div>
          <span className="text-xs text-ink-400 group-open:hidden">Show</span>
          <span className="hidden text-xs text-ink-400 group-open:inline">Hide</span>
        </div>
      </summary>
      <div className="mt-5 grid gap-4 sm:grid-cols-2">
        <Field label="Post-quantum KEM">
          <select
            className="input"
            value={opts.kemAlg}
            onChange={(e) => setOpts({ ...opts, kemAlg: e.target.value as EncodeOptions['kemAlg'] })}
          >
            <option value="ml-kem-512">ML-KEM-512 (faster, smaller)</option>
            <option value="ml-kem-768">ML-KEM-768 (default)</option>
            <option value="ml-kem-1024">ML-KEM-1024 (strongest)</option>
          </select>
        </Field>
        <Field label="Symmetric cipher">
          <select
            className="input"
            value={opts.aeadAlg}
            onChange={(e) => setOpts({ ...opts, aeadAlg: e.target.value as EncodeOptions['aeadAlg'] })}
          >
            <option value="aes-256-gcm">AES-256-GCM (default)</option>
            <option value="chacha20-poly1305">ChaCha20-Poly1305</option>
          </select>
        </Field>
        <Field label="KDF">
          <select
            className="input"
            value={opts.kdfAlg}
            onChange={(e) => setOpts({ ...opts, kdfAlg: e.target.value as EncodeOptions['kdfAlg'] })}
          >
            <option value="hkdf-sha256">HKDF-SHA-256 (default)</option>
            <option value="hkdf-sha3-256">HKDF-SHA3-256</option>
          </select>
        </Field>
        <Field label="QR error correction">
          <select
            className="input"
            value={ecc}
            onChange={(e) => setEcc(e.target.value as EccLevel)}
          >
            <option value="L">L — 7%</option>
            <option value="M">M — 15% (default)</option>
            <option value="Q">Q — 25%</option>
            <option value="H">H — 30%</option>
          </select>
        </Field>
        <Field label="Optional passphrase (adds Argon2id layer)" full>
          <input
            type="password"
            className="input"
            placeholder="leave blank to disable"
            value={opts.passphrase ?? ''}
            onChange={(e) =>
              setOpts({ ...opts, passphrase: e.target.value.length === 0 ? undefined : e.target.value })
            }
            autoComplete="new-password"
          />
        </Field>
      </div>
    </details>
  );
}

function Field({
  label,
  children,
  full,
}: {
  label: string;
  children: React.ReactNode;
  full?: boolean;
}) {
  return (
    <label className={`block text-sm ${full ? 'sm:col-span-2' : ''}`}>
      <span className="mb-1.5 block text-xs font-medium text-ink-300">{label}</span>
      {children}
    </label>
  );
}
