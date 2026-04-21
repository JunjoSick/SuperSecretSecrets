import { useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  encodeSecret,
  DEFAULT_OPTIONS,
  type EncodeOptions,
  type EncodedBundle,
} from '../crypto';
import { QrCard } from '../components/QrCard';
import { SettingsPanel } from '../components/SettingsPanel';
import { buildZip, triggerDownload } from '../lib/zip';
import type { EccLevel } from '../qr/generate';

export default function Encode() {
  const [text, setText] = useState('');
  const [opts, setOpts] = useState<EncodeOptions>({ ...DEFAULT_OPTIONS });
  const [ecc, setEcc] = useState<EccLevel>('M');
  const [bundle, setBundle] = useState<EncodedBundle | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const canGenerate = text.trim().length > 0 && !busy;
  const bytes = useMemo(() => new TextEncoder().encode(text).length, [text]);

  const generate = async () => {
    setErr(null);
    setBusy(true);
    setBundle(null);
    try {
      // Next tick so the UI shows the busy state
      await new Promise((r) => setTimeout(r, 10));
      const b = encodeSecret(text, opts);
      setBundle(b);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const reset = () => {
    setBundle(null);
    setErr(null);
  };

  const downloadZip = async () => {
    if (!bundle) return;
    const files = [
      ...bundle.headerQrs.map((p, i) => ({
        name: `header-${String(i + 1).padStart(2, '0')}-of-${bundle.headerQrs.length}`,
        payload: p,
      })),
      ...bundle.shareQrs.map((p, i) => ({
        name: `share-${String(i + 1).padStart(2, '0')}-of-${bundle.shareQrs.length}`,
        payload: p,
      })),
    ];
    const blob = await buildZip(files, ecc);
    const bid = Array.from(bundle.bundleId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    triggerDownload(blob, `supersecretsecrets-${bid.slice(0, 8)}.zip`);
  };

  return (
    <div className="mx-auto max-w-6xl px-6 pb-24 pt-10">
      <header className="mb-6 flex items-end justify-between gap-4 no-print">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-ink-50">Encode a secret</h1>
          <p className="mt-1 text-sm text-ink-400">
            Your text, a post-quantum key, and a T-of-N split — all computed in
            your browser.
          </p>
        </div>
      </header>

      {!bundle ? (
        <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
          <section className="card p-5">
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-ink-100">Your secret text</span>
              <textarea
                className="input min-h-[260px] font-mono text-sm leading-relaxed"
                placeholder="Type or paste the text you want to protect…"
                value={text}
                onChange={(e) => setText(e.target.value)}
                autoFocus
                spellCheck={false}
              />
            </label>
            <div className="mt-2 flex items-center justify-between text-xs text-ink-400">
              <span>
                {bytes} byte{bytes === 1 ? '' : 's'}
                {bytes > 1024 && ' · header will span multiple QR codes'}
              </span>
              {err && <span className="text-red-400">{err}</span>}
            </div>
          </section>

          <aside className="flex flex-col gap-4">
            <div className="card p-5">
              <h3 className="text-sm font-semibold text-ink-100">Trustees</h3>
              <p className="mt-1 text-xs text-ink-400">
                Any <span className="font-mono text-ink-200">{opts.threshold}</span> of{' '}
                <span className="font-mono text-ink-200">{opts.shares}</span> trustees can help you
                recover.
              </p>
              <div className="mt-4 space-y-4">
                <Slider
                  label="Threshold (T)"
                  min={2}
                  max={opts.shares}
                  value={opts.threshold}
                  onChange={(v) => setOpts({ ...opts, threshold: v })}
                />
                <Slider
                  label="Total shares (N)"
                  min={Math.max(opts.threshold, 2)}
                  max={12}
                  value={opts.shares}
                  onChange={(v) => setOpts({ ...opts, shares: v })}
                />
              </div>
            </div>

            <SettingsPanel opts={opts} setOpts={setOpts} ecc={ecc} setEcc={setEcc} />

            <button className="btn-primary py-3 text-base" disabled={!canGenerate} onClick={generate}>
              {busy ? 'Encrypting…' : 'Generate QR codes'}
            </button>
          </aside>
        </div>
      ) : (
        <BundleView bundle={bundle} ecc={ecc} onReset={reset} onDownloadZip={downloadZip} />
      )}
    </div>
  );
}

function BundleView({
  bundle,
  ecc,
  onReset,
  onDownloadZip,
}: {
  bundle: EncodedBundle;
  ecc: EccLevel;
  onReset: () => void;
  onDownloadZip: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35 }}
    >
      <div className="no-print mb-6 flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className="chip">{bundle.options.kemAlg}</span>
          <span className="chip">{bundle.options.aeadAlg}</span>
          <span className="chip">
            {bundle.options.threshold} of {bundle.options.shares}
          </span>
          <span className="chip">ECC {ecc}</span>
          {bundle.headerQrs.length > 1 && (
            <span className="chip">Header × {bundle.headerQrs.length}</span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-outline" onClick={onReset}>
            ← Back
          </button>
          <button className="btn-outline" onClick={() => window.print()}>
            Print
          </button>
          <button className="btn-primary" onClick={onDownloadZip}>
            Download ZIP
          </button>
        </div>
      </div>

      <div className="mb-4 text-xs text-ink-400 no-print">
        Scan <strong className="text-ink-200">all {bundle.headerQrs.length} header QR{bundle.headerQrs.length > 1 ? 's' : ''}</strong>{' '}
        plus any <strong className="text-ink-200">{bundle.options.threshold}</strong> of the{' '}
        {bundle.options.shares} share QRs to recover. Keep trustees physically separated.
      </div>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {bundle.headerQrs.map((p, i) => (
          <QrCard
            key={`h-${i}`}
            title="Header"
            accent="header"
            subtitle={bundle.headerQrs.length > 1 ? `Part ${i + 1} of ${bundle.headerQrs.length}` : undefined}
            payload={p}
            ecc={ecc}
            downloadBase={`header-${String(i + 1).padStart(2, '0')}-of-${bundle.headerQrs.length}`}
          />
        ))}
        {bundle.shareQrs.map((p, i) => (
          <QrCard
            key={`s-${i}`}
            title={`Share #${i + 1}`}
            subtitle={`1 of ${bundle.options.threshold} needed`}
            payload={p}
            ecc={ecc}
            downloadBase={`share-${String(i + 1).padStart(2, '0')}-of-${bundle.shareQrs.length}`}
          />
        ))}
      </div>
    </motion.div>
  );
}

function Slider({
  label,
  min,
  max,
  value,
  onChange,
}: {
  label: string;
  min: number;
  max: number;
  value: number;
  onChange: (v: number) => void;
}) {
  return (
    <div>
      <div className="flex items-center justify-between text-xs text-ink-300">
        <span>{label}</span>
        <span className="font-mono text-ink-100">{value}</span>
      </div>
      <input
        className="mt-1.5 w-full accent-accent-500"
        type="range"
        min={min}
        max={max}
        value={value}
        onChange={(e) => onChange(Number(e.target.value))}
      />
    </div>
  );
}
