import { useState } from 'react';
import type { EncodeOptions } from '../crypto';
import type { EccLevel } from '../qr/generate';

type Props = {
  opts: EncodeOptions;
  setOpts: (o: EncodeOptions) => void;
  ecc: EccLevel;
  setEcc: (e: EccLevel) => void;
};

export function SettingsPanel({ opts, setOpts, ecc, setEcc }: Props) {
  const [open, setOpen] = useState(false);

  return (
    <section className="card overflow-hidden">
      <div className="p-5">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="mono-upper">cipher suite</div>
            <h3 className="mt-2 text-sm font-semibold text-ink-100">Advanced options</h3>
            <p className="mt-1 text-xs leading-5 text-ink-400">
              Defaults are safe. Open this only if you need different crypto parameters or QR
              resilience.
            </p>
          </div>
          <button className="btn-outline shrink-0 text-xs" type="button" onClick={() => setOpen((v) => !v)}>
            {open ? 'Hide' : 'Configure'}
          </button>
        </div>

        <div className="mt-4 grid grid-cols-2 gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-400">
          <SummaryChip label="KEM" value={opts.kemAlg} />
          <SummaryChip label="AEAD" value={opts.aeadAlg} />
          <SummaryChip label="KDF" value={opts.kdfAlg} />
          <SummaryChip label="ECC" value={ecc} />
        </div>
      </div>

      {open && (
        <div className="grid gap-4 border-t border-white/10 bg-black/10 p-5 sm:grid-cols-2">
          <OptionGroup
            label="Post-quantum KEM"
            value={opts.kemAlg}
            onChange={(kemAlg) => setOpts({ ...opts, kemAlg: kemAlg as EncodeOptions['kemAlg'] })}
            options={[
              { value: 'ml-kem-512', label: '512', detail: 'faster / smaller' },
              { value: 'ml-kem-768', label: '768', detail: 'default' },
              { value: 'ml-kem-1024', label: '1024', detail: 'strongest' },
            ]}
          />
          <OptionGroup
            label="Symmetric cipher"
            value={opts.aeadAlg}
            onChange={(aeadAlg) => setOpts({ ...opts, aeadAlg: aeadAlg as EncodeOptions['aeadAlg'] })}
            options={[
              { value: 'aes-256-gcm', label: 'AES-GCM', detail: 'default' },
              { value: 'chacha20-poly1305', label: 'ChaCha20', detail: 'mobile-friendly' },
            ]}
          />
          <OptionGroup
            label="KDF"
            value={opts.kdfAlg}
            onChange={(kdfAlg) => setOpts({ ...opts, kdfAlg: kdfAlg as EncodeOptions['kdfAlg'] })}
            options={[
              { value: 'hkdf-sha256', label: 'SHA-256', detail: 'default' },
              { value: 'hkdf-sha3-256', label: 'SHA3-256', detail: 'alternate' },
            ]}
          />
          <OptionGroup
            label="QR error correction"
            value={ecc}
            onChange={(nextEcc) => setEcc(nextEcc as EccLevel)}
            options={[
              { value: 'L', label: 'L', detail: '7%' },
              { value: 'M', label: 'M', detail: '15% default' },
              { value: 'Q', label: 'Q', detail: '25%' },
              { value: 'H', label: 'H', detail: '30%' },
            ]}
          />
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
      )}
    </section>
  );
}

function SummaryChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-white/10 bg-white/[0.03] px-2 py-2">
      <div className="text-ink-500">{label}</div>
      <div className="mt-1 truncate text-ink-200">{value}</div>
    </div>
  );
}

function OptionGroup({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string; detail: string }>;
  onChange: (value: string) => void;
}) {
  return (
    <div className="block text-sm">
      <span className="mb-1.5 block text-xs font-medium text-ink-300">{label}</span>
      <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${options.length}, minmax(0, 1fr))` }}>
        {options.map((option) => {
          const active = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => onChange(option.value)}
              className={[
                'border px-2 py-2 text-left transition-colors',
                active
                  ? 'border-accent-300/60 bg-accent-500/10 text-accent-100'
                  : 'border-white/10 bg-white/[0.025] text-ink-300 hover:border-white/25 hover:bg-white/[0.04]',
              ].join(' ')}
            >
              <div className="text-[11px] font-medium uppercase tracking-[0.12em]">{option.label}</div>
              <div className="mt-1 text-[10px] text-ink-500">{option.detail}</div>
            </button>
          );
        })}
      </div>
    </div>
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
