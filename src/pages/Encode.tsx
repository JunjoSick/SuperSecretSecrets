import { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  encodeSecret,
  DEFAULT_OPTIONS,
  type EncodeOptions,
  type EncodedBundle,
} from '../crypto';
import { QrCard } from '../components/QrCard';
import { SettingsPanel } from '../components/SettingsPanel';
import {
  buildZip,
  DEFAULT_ZIP_CONTENT,
  triggerDownload,
  type ZipContentOptions,
} from '../lib/zip';
import type { EccLevel } from '../qr/generate';

export default function Encode() {
  const [text, setText] = useState('');
  const [opts, setOpts] = useState<EncodeOptions>({ ...DEFAULT_OPTIONS });
  const [ecc, setEcc] = useState<EccLevel>('M');
  const [bundle, setBundle] = useState<EncodedBundle | null>(null);
  const [zipContent, setZipContent] = useState<ZipContentOptions>(DEFAULT_ZIP_CONTENT);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [draftShares, setDraftShares] = useState(opts.shares);
  const [draftThreshold, setDraftThreshold] = useState(opts.threshold);

  const canGenerate = text.trim().length > 0 && !busy;
  const bytes = useMemo(() => new TextEncoder().encode(text).length, [text]);
  const lines = Math.max(text.split('\n').length, 18);

  useEffect(() => {
    setDraftShares(opts.shares);
    setDraftThreshold(opts.threshold);
  }, [opts.shares, opts.threshold]);

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
    const blob = await buildZip(files, ecc, zipContent);
    const bid = Array.from(bundle.bundleId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    triggerDownload(blob, `supersecretsecrets-${bid.slice(0, 8)}.zip`);
  };

  return (
    <div className="mx-auto max-w-7xl px-6 pb-24 pt-10">
      <header className="mb-6 flex items-end justify-between gap-4 no-print">
        <div>
          <div className="mono-upper">01 · Plaintext / parameters</div>
          <h1 className="mt-2 text-3xl font-medium tracking-tight text-ink-50">Paste the payload to seal.</h1>
          <p className="mt-1 text-sm text-ink-400">
            Your text, a post-quantum key, and a T-of-N split — all computed in
            your browser.
          </p>
        </div>
      </header>

      {!bundle ? (
        <div className="grid gap-6 lg:grid-cols-[1fr_390px]">
          <section className="card overflow-hidden">
            <label className="block">
              <span className="block border-b border-white/10 px-4 py-3 text-[10px] font-medium uppercase tracking-[0.14em] text-ink-400">
                editor · utf-8 plaintext
              </span>
              <div className="grid grid-cols-[52px_1fr]">
                <div className="line-gutter">
                  {Array.from({ length: lines }).map((_, i) => (
                    <div key={i}>{String(i + 1).padStart(2, '0')}</div>
                  ))}
                </div>
                <textarea
                  className="min-h-[380px] resize-none bg-transparent px-5 py-4 font-mono text-sm leading-relaxed text-ink-50 outline-none placeholder:text-ink-500"
                  placeholder="Type or paste the text you want to protect…"
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  autoFocus
                  spellCheck={false}
                />
              </div>
            </label>
            <div className="flex items-center justify-between border-t border-white/10 bg-white/[0.035] px-4 py-2 text-[10px] uppercase tracking-[0.14em] text-ink-500">
              <span>
                {bytes} byte{bytes === 1 ? '' : 's'}
                {bytes > 1024 && ' · header will span multiple QR codes'}
              </span>
              {err && <span className="text-red-300">{err}</span>}
            </div>
          </section>

          <aside className="flex flex-col gap-4">
            <div className="card p-5">
              <div className="mono-upper">threshold</div>
              <h3 className="mt-2 text-sm font-semibold text-ink-100">Trustees</h3>
              <p className="mt-1 text-xs text-ink-400">
                Any <span className="font-mono text-ink-200">{draftThreshold}</span> of{' '}
                <span className="font-mono text-ink-200">{draftShares}</span> trustees can help you
                recover.
              </p>
              <div className="mt-4 space-y-4">
                <Slider
                  label="Total recipients (N)"
                  min={2}
                  max={12}
                  value={opts.shares}
                  draftValue={draftShares}
                  onDraft={(v) => {
                    setDraftShares(v);
                    setDraftThreshold((current) => Math.min(current, v));
                  }}
                  onCommit={(v) =>
                    setOpts({
                      ...opts,
                      shares: v,
                      threshold: Math.min(opts.threshold, v),
                    })
                  }
                />
                <Slider
                  label="Threshold (T)"
                  min={2}
                  max={draftShares}
                  value={opts.threshold}
                  draftValue={draftThreshold}
                  onDraft={setDraftThreshold}
                  onCommit={(v) => setOpts({ ...opts, threshold: v })}
                />
              </div>
              <SharePreview shares={draftShares} threshold={draftThreshold} />
            </div>

            <SettingsPanel opts={opts} setOpts={setOpts} ecc={ecc} setEcc={setEcc} />

            <div className="card p-5">
              <div className="mono-upper mb-4">pipeline preview</div>
              <PipelineStep idx="01" title="Derive key" body="HKDF / optional Argon2id pass layer" active />
              <PipelineStep idx="02" title="Encrypt payload" body="AEAD(K, plaintext)" active />
              <PipelineStep idx="03" title="Encapsulate" body="ML-KEM public-key envelope" />
              <PipelineStep idx="04" title="Split seed" body="Shamir(K, T, N) → QR shares" />
            </div>

            <button className="btn-primary py-3 text-base" disabled={!canGenerate} onClick={generate}>
              {busy ? 'Encrypting…' : 'Generate QR codes'}
            </button>
          </aside>
        </div>
      ) : (
        <BundleView
          bundle={bundle}
          ecc={ecc}
          zipContent={zipContent}
          setZipContent={setZipContent}
          onReset={reset}
          onDownloadZip={downloadZip}
        />
      )}
    </div>
  );
}

function BundleView({
  bundle,
  ecc,
  zipContent,
  setZipContent,
  onReset,
  onDownloadZip,
}: {
  bundle: EncodedBundle;
  ecc: EccLevel;
  zipContent: ZipContentOptions;
  setZipContent: (content: ZipContentOptions) => void;
  onReset: () => void;
  onDownloadZip: () => void;
}) {
  const canDownload = zipContent.svg || zipContent.png || zipContent.txt;
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
        <div className="flex flex-wrap items-center justify-end gap-2">
          <button className="btn-outline" onClick={onReset}>
            ← Back
          </button>
          <button className="btn-outline" onClick={() => window.print()}>
            Print
          </button>
          <button className="btn-primary" onClick={onDownloadZip} disabled={!canDownload}>
            Download ZIP
          </button>
        </div>
      </div>

      <fieldset className="card no-print mb-4 flex flex-wrap items-center gap-3 px-4 py-3 text-xs text-ink-300">
        <legend className="sr-only">ZIP contents</legend>
        <span className="font-medium text-ink-100">ZIP includes</span>
        <ZipOption
          label="PNG"
          checked={zipContent.png}
          onChange={(checked) => setZipContent({ ...zipContent, png: checked })}
        />
        <ZipOption
          label="SVG"
          checked={zipContent.svg}
          onChange={(checked) => setZipContent({ ...zipContent, svg: checked })}
        />
        <ZipOption
          label="TXT payloads"
          checked={zipContent.txt}
          onChange={(checked) => setZipContent({ ...zipContent, txt: checked })}
        />
        {!canDownload && <span className="text-red-300">Pick at least one format.</span>}
      </fieldset>

      <div className="mb-4 border border-dashed border-white/10 bg-white/[0.025] px-4 py-3 text-xs text-ink-400 no-print">
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

function ZipOption({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="inline-flex items-center gap-1.5">
      <input
        type="checkbox"
        className="accent-accent-500"
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
      />
      {label}
    </label>
  );
}

function Slider({
  label,
  min,
  max,
  value,
  draftValue,
  onDraft,
  onCommit,
}: {
  label: string;
  min: number;
  max: number;
  value: number;
  draftValue: number;
  onDraft: (v: number) => void;
  onCommit: (v: number) => void;
}) {
  const clamp = (v: number) => Math.min(max, Math.max(min, v));
  const integerDraft = Math.round(clamp(draftValue));
  const commit = (raw = draftValue) => {
    const snapped = Math.round(clamp(raw));
    onDraft(snapped);
    if (snapped !== value) onCommit(snapped);
  };

  return (
    <div>
      <div className="flex items-center justify-between text-xs text-ink-300">
        <span>{label}</span>
        <span className="font-mono text-ink-100">{integerDraft}</span>
      </div>
      <input
        className="mt-1.5 w-full accent-accent-500"
        type="range"
        min={min}
        max={max}
        step={0.01}
        value={clamp(draftValue)}
        onChange={(e) => {
          onDraft(Math.round(clamp(Number(e.target.value))));
        }}
        onPointerUp={(e) => commit(Number(e.currentTarget.value))}
        onKeyUp={(e) => {
          if (e.key === 'ArrowLeft' || e.key === 'ArrowRight' || e.key === 'Home' || e.key === 'End') {
            commit(Number(e.currentTarget.value));
          }
        }}
        onBlur={(e) => commit(Number(e.currentTarget.value))}
      />
    </div>
  );
}

function SharePreview({ shares, threshold }: { shares: number; threshold: number }) {
  return (
    <div className="mt-5">
      <div className="mb-2 flex items-center justify-between text-[10px] uppercase tracking-[0.14em] text-ink-500">
        <span>distribution preview</span>
        <span className="text-accent-200">
          {threshold} / {shares}
        </span>
      </div>
      <div className="grid grid-cols-4 gap-2 sm:grid-cols-6">
        {Array.from({ length: shares }).map((_, i) => {
          const quorum = i < threshold;
          return (
            <div
              key={i}
              className={[
                'min-w-0 border px-2 py-2 text-center transition-colors duration-150',
                quorum
                  ? 'border-accent-300/60 bg-accent-500/10 text-accent-200 shadow-[0_0_24px_-18px_rgb(93_220_255)]'
                  : 'border-white/10 bg-white/[0.03] text-ink-500',
              ].join(' ')}
            >
              <div className="text-[8px] uppercase tracking-[0.08em]">S</div>
              <div className="mt-0.5 font-mono text-xs">{String(i + 1).padStart(2, '0')}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function PipelineStep({
  idx,
  title,
  body,
  active,
}: {
  idx: string;
  title: string;
  body: string;
  active?: boolean;
}) {
  return (
    <div className="mb-4 grid grid-cols-[2rem_1fr] gap-3">
      <div className={['pt-0.5 text-[10px] uppercase tracking-[0.14em]', active ? 'text-accent-300' : 'text-ink-500'].join(' ')}>
        {idx}
      </div>
      <div>
        <div className={['text-xs font-medium', active ? 'text-ink-100' : 'text-ink-300'].join(' ')}>{title}</div>
        <div className="mt-1 text-[11px] text-ink-500">{body}</div>
      </div>
    </div>
  );
}
