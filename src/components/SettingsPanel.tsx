import { useEffect, useState } from 'react';
import type { EncodeOptions } from '../crypto';
import {
  formatVdfEstimate,
  shouldCapVdfPreset,
  vdfBenchmark,
  type VdfBenchmarkResult,
} from '../crypto/vdf/benchmark';
import type { EccLevel } from '../qr/generate';

type Props = {
  opts: EncodeOptions;
  setOpts: (o: EncodeOptions) => void;
  ecc: EccLevel;
  setEcc: (e: EccLevel) => void;
};

export function SettingsPanel({ opts, setOpts, ecc, setEcc }: Props) {
  const [open, setOpen] = useState(false);
  const [vdfBench, setVdfBench] = useState<
    { status: 'idle' } | { status: 'running' } | { status: 'done'; result: VdfBenchmarkResult }
  >({ status: 'idle' });

  useEffect(() => {
    if (!open || vdfBench.status !== 'idle') return;
    let cancelled = false;
    setVdfBench({ status: 'running' });
    const id = window.setTimeout(() => {
      const result = vdfBenchmark();
      if (!cancelled) setVdfBench({ status: 'done', result });
    }, 0);
    return () => {
      cancelled = true;
      window.clearTimeout(id);
    };
  }, [open, vdfBench.status]);

  const benchmark = vdfBench.status === 'done' ? vdfBench.result : null;
  const proof = proofReadiness(opts);

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
          <SummaryChip label="Proof" value={proof.summary} />
          <SummaryChip label="Mode" value={opts.vaultMode ? 'vault' : 'single'} />
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
          <Field label="v3 zero-knowledge commitments (policy + plaintext + vault tree)" full>
            <label className="flex items-start gap-2 text-xs text-ink-300">
              <input
                type="checkbox"
                checked={!!opts.zk}
                onChange={(e) => setOpts({ ...opts, zk: e.target.checked || undefined })}
              />
              <span>
                Bind a binding hash of the policy manifest, plaintext, and vault structure into the
                bundle so any tamper after publication is detectable. <em>Not post-quantum.</em>
              </span>
            </label>
          </Field>
          <Field label="Auditor decryption proof" full>
            <div className={['overflow-hidden border p-0', proof.card].join(' ')}>
              <div className="grid gap-4 p-4 md:grid-cols-[1fr_auto] md:items-start">
                <div className="min-w-0">
                  <div className={['mono-upper', proof.kicker].join(' ')}>{proof.kickerText}</div>
                  <h4 className="mt-2 text-sm font-semibold text-ink-100">{proof.title}</h4>
                  <p className="mt-2 max-w-2xl text-xs leading-6 text-ink-400">{proof.body}</p>
                </div>
                <div className="flex flex-wrap gap-2 md:max-w-[17rem] md:justify-end">
                  <span className={['chip', proof.chip].join(' ')}>{proof.summary}</span>
                  <span className={opts.vaultMode ? 'chip border-accent-300/30 text-accent-200' : 'chip border-white/10 text-ink-500'}>
                    {opts.vaultMode ? 'vault mode' : 'needs vault'}
                  </span>
                  <span className={opts.zk ? 'chip border-accent-300/30 text-accent-200' : 'chip border-white/10 text-ink-500'}>
                    {opts.zk ? 'commitments on' : 'commitments off'}
                  </span>
                </div>
              </div>
              <div className="grid gap-3 border-t border-white/10 bg-black/20 p-4 sm:grid-cols-2">
                <button
                  type="button"
                  className="btn-outline min-h-11 justify-center px-3 py-2 text-[10px]"
                  onClick={() => setOpts({ ...opts, vaultMode: true, zk: true })}
                >
                  Prepare proof settings
                </button>
                <button
                  type="button"
                  className="btn-outline min-h-11 justify-center px-3 py-2 text-[10px]"
                  disabled
                >
                  Prover backend not bundled
                </button>
              </div>
            </div>
          </Field>
          <OptionGroup
            label="VDF time-lock difficulty (per-share Wesolowski class-group VDF)"
            value={vdfPreset(opts.vdf)}
            onChange={(v) => setOpts({ ...opts, vdf: vdfFromPreset(v) })}
            options={vdfPresetOptions(benchmark)}
          />
          <p className="sm:col-span-2 -mt-2 text-[11px] leading-5 text-ink-500">
            {vdfBenchmarkText(vdfBench)}
          </p>
          {opts.vdf && (
            <p className="sm:col-span-2 -mt-2 text-[11px] leading-5 text-ink-500">
              VDF locks each share behind T sequential squarings in a class group of unknown
              order. Encode and recovery each pay the wall-clock cost.{' '}
              <strong className="text-ink-300">Not post-quantum.</strong>{' '}
              {benchmark ? `Current preset estimate: ${formatVdfEstimate(opts.vdf.T, benchmark)} per share.` : ''}
            </p>
          )}
        </div>
      )}
    </section>
  );
}

function vdfPreset(vdf: EncodeOptions['vdf']): string {
  if (!vdf) return 'off';
  if (vdf.T === 1n << 14n) return 'light';
  if (vdf.T === 1n << 16n) return 'medium';
  if (vdf.T === 1n << 20n) return 'slow';
  return 'off';
}

function vdfFromPreset(v: string): EncodeOptions['vdf'] | undefined {
  switch (v) {
    case 'light':
      return { T: 1n << 14n, discriminantBits: 128 };
    case 'medium':
      return { T: 1n << 16n, discriminantBits: 128 };
    case 'slow':
      return { T: 1n << 20n, discriminantBits: 128 };
    default:
      return undefined;
  }
}

function vdfPresetOptions(benchmark: VdfBenchmarkResult | null) {
  const estimate = (T: bigint) => (benchmark ? `~${formatVdfEstimate(T, benchmark)}` : `T = 2^${log2(T)}`);
  const slowDisabled = benchmark ? shouldCapVdfPreset(1n << 20n, benchmark) : false;
  return [
    { value: 'off', label: 'Off', detail: 'no VDF' },
    { value: 'light', label: 'Light', detail: estimate(1n << 14n) },
    { value: 'medium', label: 'Medium', detail: estimate(1n << 16n) },
    {
      value: 'slow',
      label: 'Slow',
      detail: slowDisabled ? 'capped here' : estimate(1n << 20n),
      disabled: slowDisabled,
    },
  ];
}

function vdfBenchmarkText(
  state: { status: 'idle' } | { status: 'running' } | { status: 'done'; result: VdfBenchmarkResult },
): string {
  if (state.status === 'idle') return 'Open advanced options to estimate local VDF runtime.';
  if (state.status === 'running') return 'Benchmarking local VDF throughput...';
  const medium = formatVdfEstimate(1n << 16n, state.result);
  const slow = formatVdfEstimate(1n << 20n, state.result);
  const cap = state.result.mobileLikely ? ' Mobile cap active above Medium.' : '';
  return `Local VDF estimate: Medium ~${medium}/share, Slow ~${slow}/share.${cap}`;
}

function log2(value: bigint): string {
  let exponent = 0;
  let v = value;
  while (v > 1n) {
    v >>= 1n;
    exponent++;
  }
  return String(exponent);
}

function SummaryChip({ label, value }: { label: string; value: string }) {
  return (
    <div className="min-w-0 border border-white/10 bg-white/[0.03] px-2 py-2">
      <div className="text-ink-500">{label}</div>
      <div className="mt-1 break-words leading-4 text-ink-200">{value}</div>
    </div>
  );
}

function proofReadiness(opts: EncodeOptions): {
  summary: string;
  kickerText: string;
  title: string;
  body: string;
  card: string;
  chip: string;
  kicker: string;
} {
  const passphraseEnabled = !!(opts.passphrase && opts.passphrase.length > 0);
  const supported =
    opts.vaultMode === true &&
    opts.kemAlg === 'ml-kem-768' &&
    opts.kdfAlg === 'hkdf-sha256' &&
    opts.aeadAlg === 'aes-256-gcm' &&
    !passphraseEnabled;
  if (supported) {
    return {
      summary: 'ready',
      kickerText: 'proof relation ready',
      title: 'This bundle matches the proof-backed vault format.',
      body:
        'The selected vault-root settings match the current proof transcript and Poseidon2 commitment format. Proof emission still needs a bundled prover backend.',
      card: 'border-accent-300/30 bg-accent-500/5',
      chip: 'border-accent-300/30 text-accent-200',
      kicker: 'text-accent-300',
    };
  }
  const blockers = [
    opts.vaultMode !== true ? 'vault mode' : null,
    opts.kemAlg !== 'ml-kem-768' ? 'ML-KEM-768' : null,
    opts.kdfAlg !== 'hkdf-sha256' ? 'HKDF-SHA256' : null,
    opts.aeadAlg !== 'aes-256-gcm' ? 'AES-GCM' : null,
    passphraseEnabled ? 'no passphrase' : null,
  ].filter(Boolean);
  return {
    summary: 'not eligible',
    kickerText: 'proof relation gated',
    title: 'Adjust settings before proof emission.',
    body: `The current proof relation needs ${blockers.join(', ')}. Recovery and v3 commitments still work without a decryption proof.`,
    card: 'border-amber-300/25 bg-amber-500/5',
    chip: 'border-amber-300/30 text-amber-200',
    kicker: 'text-amber-300',
  };
}

function OptionGroup({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: Array<{ value: string; label: string; detail: string; disabled?: boolean }>;
  onChange: (value: string) => void;
}) {
  return (
    <div className="block text-sm">
      <span className="mb-1.5 block text-xs font-medium text-ink-300">{label}</span>
      <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(options.length, 2)}, minmax(0, 1fr))` }}>
        {options.map((option) => {
          const active = option.value === value;
          return (
            <button
              key={option.value}
              type="button"
              onClick={() => {
                if (!option.disabled) onChange(option.value);
              }}
              disabled={option.disabled}
              className={[
                'min-h-16 min-w-0 border px-2.5 py-2 text-left transition-colors',
                option.disabled
                  ? 'cursor-not-allowed border-white/5 bg-white/[0.015] text-ink-600'
                  : active
                  ? 'border-accent-300/60 bg-accent-500/10 text-accent-100'
                  : 'border-white/10 bg-white/[0.025] text-ink-300 hover:border-white/25 hover:bg-white/[0.04]',
              ].join(' ')}
            >
              <div className="break-words text-[11px] font-medium uppercase leading-4 tracking-[0.08em]">{option.label}</div>
              <div className="mt-1 break-words text-[10px] leading-4 text-ink-500">{option.detail}</div>
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
    <div className={`block text-sm ${full ? 'sm:col-span-2' : ''}`}>
      <span className="mb-1.5 block text-xs font-medium text-ink-300">{label}</span>
      {children}
    </div>
  );
}
