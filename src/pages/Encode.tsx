import { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import {
  DEFAULT_OPTIONS,
  type EncodeOptions,
  type EncodedBundle,
  type VaultEntry,
} from '../crypto';
import { QrCard } from '../components/QrCard';
import { SettingsPanel } from '../components/SettingsPanel';
import { WorkerProgressCard } from '../components/WorkerProgress';
import {
  buildZip,
  DEFAULT_ZIP_CONTENT,
  triggerDownload,
  type ZipContentOptions,
} from '../lib/zip';
import type { EccLevel } from '../qr/generate';
import type { EncodeWorkerRequest, WorkerEvent, WorkerProgressEvent } from '../workers/protocol';

type ImagePayload = {
  id: string;
  name: string;
  contentType: string;
  data: Uint8Array;
  previewUrl: string;
  metadataMode: 'preserve' | 'stripped';
};

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
  const [encodeProgress, setEncodeProgress] = useState<WorkerProgressEvent | null>(null);
  const [imagePayload, setImagePayload] = useState<ImagePayload | null>(null);
  const [stripImageMetadata, setStripImageMetadata] = useState(false);
  const encodeSeq = useRef(0);
  const workerRef = useRef<Worker | null>(null);

  const canGenerate = (text.trim().length > 0 || imagePayload !== null) && !busy;
  const bytes = useMemo(() => new TextEncoder().encode(text).length, [text]);
  const lines = Math.max(text.split('\n').length, 18);
  const vaultMode = opts.vaultMode === true || imagePayload !== null;
  const proofState = proofUiState({ ...opts, vaultMode });
  const payloadLabel = imagePayload
    ? `${imagePayload.name} · ${formatBytes(imagePayload.data.length)}`
    : text.trim().length > 0
    ? `${bytes} byte${bytes === 1 ? '' : 's'}`
    : 'awaiting payload';
  const suiteLabel = `${opts.kemAlg.toUpperCase()} / ${
    opts.aeadAlg === 'aes-256-gcm' ? 'AES-GCM' : 'ChaCha20'
  }`;

  useEffect(() => {
    setDraftShares(opts.shares);
    setDraftThreshold(opts.threshold);
  }, [opts.shares, opts.threshold]);

  useEffect(() => {
    return () => workerRef.current?.terminate();
  }, []);

  useEffect(() => {
    return () => {
      if (imagePayload?.previewUrl) URL.revokeObjectURL(imagePayload.previewUrl);
    };
  }, [imagePayload?.previewUrl]);

  const finishWorker = (worker: Worker) => {
    worker.terminate();
    if (workerRef.current === worker) workerRef.current = null;
  };

  const generate = () => {
    if (!canGenerate) return;
    workerRef.current?.terminate();
    const id = ++encodeSeq.current;
    const worker = new Worker(new URL('../workers/encode.worker.ts', import.meta.url), {
      type: 'module',
    });
    workerRef.current = worker;
    setErr(null);
    setBusy(true);
    setBundle(null);
    setEncodeProgress(null);

    const selectedImage = imagePayload;
    const imageEntry = selectedImage ? imagePayloadToVaultEntry(selectedImage) : null;
    const requestOptions: Partial<EncodeOptions> = imageEntry
      ? { ...opts, vaultMode: true, vaultEntries: [imageEntry] }
      : opts;
    const plaintext = selectedImage ? selectedImage.name : text;

    worker.onmessage = (event: MessageEvent<WorkerEvent>) => {
      if (event.data.id !== encodeSeq.current) return;
      if (event.data.type === 'progress') {
        setEncodeProgress(event.data);
        return;
      }
      if (event.data.type === 'result' && event.data.op === 'encode') {
        setBundle(event.data.result);
      } else if (event.data.type === 'error') {
        setErr(event.data.error);
      }
      setBusy(false);
      setEncodeProgress(null);
      finishWorker(worker);
    };

    worker.onerror = () => {
      if (id !== encodeSeq.current) return;
      setErr('encode worker failed');
      setBusy(false);
      setEncodeProgress(null);
      finishWorker(worker);
    };

    worker.postMessage({
      type: 'encode',
      id,
      plaintext,
      options: requestOptions,
    } satisfies EncodeWorkerRequest);
  };

  const cancelGenerate = () => {
    const worker = workerRef.current;
    if (worker) {
      worker.postMessage({ type: 'cancel', id: encodeSeq.current } satisfies EncodeWorkerRequest);
      worker.terminate();
      workerRef.current = null;
    }
    encodeSeq.current++;
    setBusy(false);
    setEncodeProgress(null);
  };

  const reset = () => {
    cancelGenerate();
    setBundle(null);
    setErr(null);
  };

  const importImage = async (file: File | null) => {
    setErr(null);
    if (!file) return;
    if (!file.type.toLowerCase().startsWith('image/')) {
      setErr('choose an image file');
      return;
    }
    try {
      const sanitized = stripImageMetadata ? await stripImageFileMetadata(file) : null;
      const bytes = sanitized?.data ?? new Uint8Array(await file.arrayBuffer());
      const contentType = sanitized?.contentType ?? file.type ?? 'application/octet-stream';
      const name = sanitized?.name ?? file.name ?? 'image';
      const previewBlob = new Blob([bytes.slice().buffer as ArrayBuffer], { type: contentType });
      setImagePayload({
        id: 'image',
        name,
        contentType,
        data: bytes,
        previewUrl: URL.createObjectURL(previewBlob),
        metadataMode: sanitized ? 'stripped' : 'preserve',
      });
      setOpts((current) => ({ ...current, vaultMode: true }));
      setBundle(null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'could not read image');
    }
  };

  const clearImagePayload = () => {
    setImagePayload(null);
    setBundle(null);
  };

  const downloadZip = async () => {
    if (!bundle) return;
    const bid = Array.from(bundle.bundleId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
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
    const attachments = bundle.vaultBlob
      ? [{ name: `vault-${bid.slice(0, 8)}.ssssvault`, data: bundle.vaultBlob }]
      : [];
    const blob = await buildZip(files, ecc, zipContent, attachments);
    triggerDownload(blob, `supersecretsecrets-${bid.slice(0, 8)}.zip`);
  };

  return (
    <div className="mx-auto max-w-7xl px-4 pb-24 pt-8 sm:px-6 lg:pt-10">
      <header className="mb-6 grid gap-4 no-print lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
        <div className="min-w-0">
          <div className="mono-upper">01 · encode</div>
          <h1 className="mt-2 text-balance text-3xl font-medium tracking-tight text-ink-50">
            Seal a secret into recoverable QR shares.
          </h1>
          <p className="mt-2 max-w-2xl text-sm leading-6 text-ink-400">
            Build a local-only bundle with post-quantum encapsulation, threshold recovery, optional vault export, and v3 audit commitments.
          </p>
        </div>
        <EncodeCrumbs active={bundle ? 'shares' : busy ? 'sealing' : canGenerate ? 'parameters' : 'payload'} />
      </header>

      {!bundle ? (
        <>
          <OperationStrip
            items={[
              ['mode', vaultMode ? 'vault · blob' : 'plaintext'],
              ['payload', payloadLabel],
              ['threshold', `${draftThreshold} of ${draftShares}`],
              ['suite', suiteLabel],
              ['proof', proofState.badge],
            ]}
          />

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(340px,420px)]">
            <section className="grid min-w-0 gap-4">
              <section className="card overflow-hidden">
                <div className="grid gap-4 border-b border-white/10 bg-white/[0.025] p-4 lg:grid-cols-[minmax(0,1fr)_minmax(18rem,24rem)] lg:items-start">
                  <div className="min-w-0">
                    <div className="mono-upper">payload composer</div>
                    <h2 className="mt-2 text-lg font-medium tracking-tight text-ink-50">
                      {vaultMode ? 'Build the vault payload.' : 'Paste the plaintext payload.'}
                    </h2>
                    <p className="mt-1 max-w-xl text-xs leading-5 text-ink-400">
                      {vaultMode
                        ? 'The QR shares recover the key; the vault blob carries the sealed file content.'
                        : 'The QR shares carry everything needed to recover this plaintext.'}
                    </p>
                  </div>
                  <div className="grid min-w-0 grid-cols-2 gap-2">
                    <ModeButton
                      active={!vaultMode}
                      label="Plaintext"
                      detail="QR only"
                      onClick={() => {
                        clearImagePayload();
                        setOpts({ ...opts, vaultMode: false, vaultEntries: undefined });
                      }}
                    />
                    <ModeButton
                      active={vaultMode}
                      label="Vault"
                      detail="QR + blob"
                      onClick={() => setOpts({ ...opts, vaultMode: true })}
                    />
                  </div>
                </div>

                <label className="block">
                  <span className="sr-only">Plaintext payload</span>
                  <div className="grid grid-cols-[44px_minmax(0,1fr)] sm:grid-cols-[52px_minmax(0,1fr)]">
                    <div className="line-gutter">
                      {Array.from({ length: lines }).map((_, i) => (
                        <div key={i}>{String(i + 1).padStart(2, '0')}</div>
                      ))}
                    </div>
                    <textarea
                      className="block min-h-[340px] w-full resize-y bg-transparent px-4 py-4 font-mono text-sm leading-relaxed text-ink-50 outline-none placeholder:text-ink-500 sm:min-h-[390px] sm:px-5"
                      placeholder="Type or paste the text you want to protect..."
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      autoFocus
                      spellCheck={false}
                    />
                  </div>
                </label>

                <ImagePayloadPanel
                  image={imagePayload}
                  stripMetadata={stripImageMetadata}
                  onStripMetadataChange={setStripImageMetadata}
                  onImport={importImage}
                  onClear={clearImagePayload}
                />

                <div className="grid gap-2 border-t border-white/10 bg-white/[0.035] px-4 py-2 text-[10px] uppercase tracking-[0.14em] text-ink-500 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                  <span className="min-w-0 break-words">
                    {imagePayload
                      ? `${formatBytes(imagePayload.data.length)} image · ${
                          imagePayload.metadataMode === 'stripped' ? 'metadata stripped' : 'exact bytes'
                        }`
                      : `${bytes} byte${bytes === 1 ? '' : 's'}${bytes > 1024 ? ' · header will span multiple QR codes' : ''}`}
                  </span>
                  {err && <span className="min-w-0 break-words text-red-300">{err}</span>}
                </div>
              </section>
            </section>

            <aside className="flex min-w-0 flex-col gap-4">
              <OperationDigest
                rows={[
                  ['payload', payloadLabel],
                  ['cipher suite', suiteLabel],
                  ['secret sharing', `Shamir ${draftThreshold}-of-${draftShares}`],
                  ['QR resilience', `ECC ${ecc}`],
                  ['output', vaultMode ? 'header QR + share QR + .ssssvault' : 'header QR + share QR'],
                ]}
              />

              <div className="card overflow-hidden">
                <div className="border-b border-white/10 bg-white/[0.025] p-5">
                  <div className="mono-upper">threshold</div>
                  <div className="mt-3 flex flex-wrap items-end justify-between gap-3">
                    <div className="min-w-0">
                      <h3 className="text-sm font-semibold text-ink-100">Trustee distribution</h3>
                      <p className="mt-1 text-xs leading-5 text-ink-400">
                        Any <span className="font-mono text-ink-200">{draftThreshold}</span> of{' '}
                        <span className="font-mono text-ink-200">{draftShares}</span> shares can recover.
                      </p>
                    </div>
                    <span className="chip border-accent-300/30 text-accent-200">
                      loss budget {Math.max(0, draftShares - draftThreshold)}
                    </span>
                  </div>
                </div>
                <div className="p-5">
                  <div className="space-y-4">
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
              </div>

              <SettingsPanel opts={opts} setOpts={setOpts} ecc={ecc} setEcc={setEcc} />

              <div className="card p-5">
                <div className="mb-4 flex items-center justify-between gap-3">
                  <div className="mono-upper">pipeline preview</div>
                  <span className="text-[10px] uppercase tracking-[0.14em] text-accent-300">local only</span>
                </div>
                <PipelineStep idx="01" title="Derive key" body="HKDF with optional Argon2id pass layer" active />
                <PipelineStep
                  idx="02"
                  title={vaultMode ? 'Seal vault root' : 'Encrypt payload'}
                  body={vaultMode ? 'AEAD protects the vault root key and exported blob' : 'AEAD protects the plaintext bytes'}
                  active
                />
                <PipelineStep idx="03" title="Encapsulate" body="ML-KEM public-key recovery envelope" active />
                <PipelineStep
                  idx="04"
                  title={vaultMode ? 'Emit vault package' : 'Split seed'}
                  body={vaultMode ? 'Vault blob plus QR shares' : 'Shamir threshold shares'}
                  active
                />
                {opts.zk && (
                  <PipelineStep idx="05" title="Commit v3 state" body="Policy, plaintext, shares, and vault tree" active />
                )}
                {opts.vdf && (
                  <PipelineStep
                    idx={opts.zk ? '06' : '05'}
                    title="VDF-lock shares"
                    body="Sequential class-group delay per share"
                    active
                  />
                )}
                <PipelineStep
                  idx={opts.vdf ? (opts.zk ? '07' : '06') : opts.zk ? '06' : '05'}
                  title="Auditor proof"
                  body={proofState.pipeline}
                  active={proofState.ready}
                />
              </div>

              <div className={['card p-5', proofState.card].join(' ')}>
                <div className={['mono-upper', proofState.kicker].join(' ')}>auditor proof</div>
                <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
                  <h3 className="min-w-0 text-sm font-semibold leading-5 text-ink-100">{proofState.title}</h3>
                  <span className={['chip', proofState.chip].join(' ')}>{proofState.badge}</span>
                </div>
                <p className="mt-2 text-xs leading-6 text-ink-400">{proofState.body}</p>
              </div>

              {busy && (
                <WorkerProgressCard
                  title="Generating bundle"
                  fallback="Preparing cryptographic material."
                  progress={encodeProgress}
                />
              )}

              <div className="card grid gap-3 p-4">
                <button className="btn-primary min-h-12 text-sm sm:text-base" disabled={!canGenerate} onClick={generate}>
                  {busy ? 'Generating bundle' : 'Seal and generate shares'}
                </button>
                {busy && (
                  <button className="btn-outline min-h-11 text-sm" type="button" onClick={cancelGenerate}>
                    Cancel
                  </button>
                )}
              </div>
            </aside>
          </div>
        </>
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

async function stripImageFileMetadata(
  file: File,
): Promise<{ data: Uint8Array; contentType: string; name: string }> {
  const bitmap = await createImageBitmap(file);
  try {
    const canvas = document.createElement('canvas');
    canvas.width = bitmap.width;
    canvas.height = bitmap.height;
    const ctx = canvas.getContext('2d');
    if (!ctx) throw new Error('could not create image canvas');
    ctx.drawImage(bitmap, 0, 0);
    const contentType = file.type.toLowerCase() === 'image/jpeg' ? 'image/jpeg' : 'image/png';
    const blob = await new Promise<Blob>((resolve, reject) => {
      canvas.toBlob(
        (result) => {
          if (result) resolve(result);
          else reject(new Error('could not strip image metadata'));
        },
        contentType,
        contentType === 'image/jpeg' ? 0.92 : undefined,
      );
    });
    return {
      data: new Uint8Array(await blob.arrayBuffer()),
      contentType,
      name: imageNameForContentType(file.name || 'image', contentType),
    };
  } finally {
    bitmap.close();
  }
}

function imageNameForContentType(name: string, contentType: string): string {
  const base = name.replace(/\.[^.]*$/, '') || 'image';
  if (contentType === 'image/jpeg') return `${base}.jpg`;
  return `${base}.png`;
}

function imagePayloadToVaultEntry(image: ImagePayload): VaultEntry {
  return {
    id: image.id,
    name: image.name,
    contentType: image.contentType,
    data: image.data,
  };
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

function proofUiState(opts: EncodeOptions): {
  ready: boolean;
  badge: string;
  title: string;
  body: string;
  pipeline: string;
  card: string;
  chip: string;
  kicker: string;
} {
  const passphraseEnabled = !!(opts.passphrase && opts.passphrase.length > 0);
  const ready =
    opts.vaultMode === true &&
    opts.kemAlg === 'ml-kem-768' &&
    opts.aeadAlg === 'aes-256-gcm' &&
    opts.kdfAlg === 'hkdf-sha256' &&
    !passphraseEnabled;
  if (ready) {
    return {
      ready: true,
      badge: 'relation ready',
      title: 'Ready for a QR-carried proof backend.',
      body:
        'These settings match the current vault-root proof relation. This build still needs a bundled prover before it can attach the proof TLV.',
      pipeline: 'Relation ready; prover backend not bundled',
      card: 'border-accent-300/30 bg-accent-500/5',
      chip: 'border-accent-300/30 text-accent-200',
      kicker: 'text-accent-300',
    };
  }
  return {
    ready: false,
    badge: 'not eligible',
    title: 'Proof emission is gated by the current settings.',
    body:
      'The first relation requires vault mode, ML-KEM-768, HKDF-SHA256, AES-256-GCM, and no passphrase. Recovery and commitments remain available.',
    pipeline: 'Unavailable for the selected relation',
    card: 'border-white/10 bg-white/[0.02]',
    chip: 'border-white/10 text-ink-400',
    kicker: 'text-ink-500',
  };
}

function ImagePayloadPanel({
  image,
  stripMetadata,
  onStripMetadataChange,
  onImport,
  onClear,
}: {
  image: ImagePayload | null;
  stripMetadata: boolean;
  onStripMetadataChange: (strip: boolean) => void;
  onImport: (file: File | null) => void;
  onClear: () => void;
}) {
  const [dragOver, setDragOver] = useState(false);

  return (
    <div className="border-t border-white/10 bg-black/10 p-4">
      {!image ? (
        <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
          <label
            className={[
              'grid min-h-28 cursor-pointer gap-2 border border-dashed px-4 py-4 transition-colors',
              dragOver
                ? 'border-accent-300/60 bg-accent-500/10'
                : 'border-white/10 bg-white/[0.025] hover:border-white/25 hover:bg-white/[0.04]',
            ].join(' ')}
            onDragEnter={() => setDragOver(true)}
            onDragLeave={() => setDragOver(false)}
            onDragOver={(event) => {
              event.preventDefault();
              setDragOver(true);
            }}
            onDrop={(event) => {
              event.preventDefault();
              setDragOver(false);
              void onImport(event.dataTransfer.files?.[0] ?? null);
            }}
          >
            <span className="mono-upper">image payload</span>
            <span className="max-w-xl text-sm font-medium text-ink-100">Drop an image or choose one for vault mode.</span>
            <span className="text-xs leading-5 text-ink-400">
              Image bytes are sealed into a .ssssvault blob while the QR shares recover the decryption key.
            </span>
            <input
              type="file"
              accept="image/*"
              className="hidden"
              onChange={(e) => {
                void onImport(e.target.files?.[0] ?? null);
                e.currentTarget.value = '';
              }}
            />
          </label>
          <div className="flex flex-wrap items-center gap-3 lg:block lg:min-w-[9rem]">
            <label className="inline-flex items-center gap-2 text-xs text-ink-300 lg:mb-3 lg:flex">
              <input
                type="checkbox"
                className="accent-accent-500"
                checked={stripMetadata}
                onChange={(e) => onStripMetadataChange(e.target.checked)}
              />
              <span>Strip metadata</span>
            </label>
            <label className="btn-outline cursor-pointer text-xs">
              Choose image
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => {
                  void onImport(e.target.files?.[0] ?? null);
                  e.currentTarget.value = '';
                }}
              />
            </label>
          </div>
        </div>
      ) : (
        <div className="grid gap-4 sm:grid-cols-[112px_minmax(0,1fr)_auto] sm:items-center">
          <img
            src={image.previewUrl}
            alt=""
            className="h-24 w-28 border border-white/10 bg-black/20 object-contain"
          />
          <div className="min-w-0">
            <div className="mono-upper">vault image</div>
            <div className="mt-1 min-w-0 break-words text-sm font-medium text-ink-100">{image.name}</div>
            <div className="mt-2 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-500">
              <span>{formatBytes(image.data.length)}</span>
              <span>{image.contentType}</span>
              <span>{image.metadataMode === 'stripped' ? 'stripped' : 'exact bytes'}</span>
            </div>
          </div>
          <button type="button" className="btn-ghost text-xs" onClick={onClear}>
            Remove
          </button>
        </div>
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
  const hasVaultBlob = !!bundle.vaultBlob;
  const proofState = proofUiState(bundle.options);
  const canDownload = zipContent.svg || zipContent.png || zipContent.txt || hasVaultBlob;
  const bid = Array.from(bundle.bundleId)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  const downloadVaultBlob = () => {
    if (!bundle.vaultBlob) return;
    const copy = new Uint8Array(bundle.vaultBlob);
    triggerDownload(
      new Blob([copy.buffer as ArrayBuffer], { type: 'application/octet-stream' }),
      `vault-${bid.slice(0, 8)}.ssssvault`,
    );
  };
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
          {hasVaultBlob && <span className="chip border-amber-300/30 text-amber-200">Vault</span>}
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
          {hasVaultBlob && (
            <button className="btn-outline" onClick={downloadVaultBlob}>
              Download vault
            </button>
          )}
          <button className="btn-primary" onClick={onDownloadZip} disabled={!canDownload}>
            Download ZIP
          </button>
        </div>
      </div>

      <BundleIntegrityStrip
        bid={bid}
        mode={hasVaultBlob ? 'vault · blob' : 'plaintext'}
        suite={`${bundle.options.kemAlg.toUpperCase()} / ${
          bundle.options.aeadAlg === 'aes-256-gcm' ? 'AES-GCM' : 'ChaCha20'
        }`}
        threshold={`${bundle.options.threshold} of ${bundle.options.shares}`}
        extras={[bundle.options.zk && 'v3 commitments', bundle.options.vdf && 'VDF lock', hasVaultBlob && '.ssssvault']
          .filter(Boolean)
          .join(' · ') || 'none'}
      />

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
        {hasVaultBlob && <span className="chip border-amber-300/30 text-amber-200">.ssssvault included</span>}
        {!canDownload && <span className="text-red-300">Pick at least one format.</span>}
      </fieldset>

      <div className="no-print mb-4 grid gap-3 border border-dashed border-white/10 bg-white/[0.025] px-4 py-3 text-xs leading-5 text-ink-400 md:grid-cols-[auto_1fr] md:items-center">
        <span className="chip border-accent-300/30 text-accent-200">recovery set</span>
        <span className="min-w-0 break-words">
          Scan <strong className="text-ink-200">all {bundle.headerQrs.length} header QR{bundle.headerQrs.length > 1 ? 's' : ''}</strong>{' '}
          plus any <strong className="text-ink-200">{bundle.options.threshold}</strong> of the{' '}
          {bundle.options.shares} share QRs to recover. {hasVaultBlob ? 'Recover also needs the .ssssvault blob.' : 'Keep trustees physically separated.'}
        </span>
      </div>
      {bundle.options.zk && (
        <div className="mb-4 grid gap-3 border border-amber-300/20 bg-amber-500/5 px-4 py-3 text-xs text-amber-100 no-print md:grid-cols-[auto_1fr] md:items-center">
          <span className={['chip', proofState.ready ? 'border-accent-300/30 text-accent-200' : 'border-amber-300/30 text-amber-200'].join(' ')}>
            {proofState.ready ? 'proof-ready settings' : 'commitments only'}
          </span>
          <span className="leading-5 text-ink-300">
            This bundle includes v3 commitments and share proofs. An auditor proof TLV is emitted only when a local prover backend is configured.
          </span>
        </div>
      )}

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

function EncodeCrumbs({ active }: { active: 'payload' | 'parameters' | 'sealing' | 'shares' }) {
  const activeId = active === 'sealing' ? 'shares' : active;
  const items = [
    ['payload', 'Plaintext'],
    ['parameters', 'Parameters'],
    ['shares', active === 'sealing' ? 'Sealing' : 'Shares'],
  ] as const;
  const activeIndex = items.findIndex(([id]) => id === activeId);

  return (
    <div className="hidden max-w-full flex-wrap items-center justify-end gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-500 md:flex">
      {items.map(([id, label], index) => {
        const activeItem = id === activeId;
        const done = index < activeIndex;
        return (
          <div key={id} className="flex min-w-0 items-center gap-2">
            {index > 0 && <span className="text-ink-600">/</span>}
            <span className={activeItem ? 'text-accent-200' : done ? 'text-ink-300' : 'text-ink-600'}>
              {String(index + 1).padStart(2, '0')} {label}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function OperationStrip({ items }: { items: Array<[string, string]> }) {
  return (
    <div className="card no-print mb-6 grid overflow-hidden sm:grid-cols-2 lg:grid-cols-5">
      {items.map(([label, value], index) => (
        <div
          key={label}
          className={[
            'min-w-0 border-white/10 px-4 py-3',
            index < items.length - 1 ? 'border-b sm:border-r lg:border-b-0' : '',
            index === 1 ? 'lg:border-b-0' : '',
          ].join(' ')}
        >
          <div className="mono-upper">{label}</div>
          <div className="mt-1 min-w-0 break-words text-xs leading-5 text-ink-100">{value}</div>
        </div>
      ))}
    </div>
  );
}

function OperationDigest({ rows }: { rows: Array<[string, string]> }) {
  return (
    <section className="card p-5">
      <div className="mono-upper">operation digest</div>
      <div className="mt-4 grid gap-1">
        {rows.map(([label, value]) => (
          <div key={label} className="grid grid-cols-[7rem_minmax(0,1fr)] gap-3 border-b border-dashed border-white/10 py-2 text-xs">
            <span className="min-w-0 break-words uppercase tracking-[0.08em] text-ink-500">{label}</span>
            <span className="min-w-0 break-words text-right text-ink-100">{value}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function BundleIntegrityStrip({
  bid,
  mode,
  suite,
  threshold,
  extras,
}: {
  bid: string;
  mode: string;
  suite: string;
  threshold: string;
  extras: string;
}) {
  return (
    <div className="card no-print mb-4 grid overflow-hidden sm:grid-cols-2 lg:grid-cols-5">
      {[
        ['bundle id', bid.slice(0, 8)],
        ['mode', mode],
        ['suite', suite],
        ['threshold', threshold],
        ['extras', extras],
      ].map(([label, value], index) => (
        <div
          key={label}
          className={[
            'min-w-0 border-white/10 px-4 py-3',
            index < 4 ? 'border-b sm:border-r lg:border-b-0' : '',
          ].join(' ')}
        >
          <div className="mono-upper">{label}</div>
          <div className="mt-1 min-w-0 break-words text-xs leading-5 text-ink-100">{value}</div>
        </div>
      ))}
    </div>
  );
}

function ModeButton({
  active,
  label,
  detail,
  onClick,
}: {
  active: boolean;
  label: string;
  detail: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        'border px-3 py-2 text-left transition-colors',
        active
          ? 'border-accent-300/60 bg-accent-500/10 text-accent-100'
          : 'border-white/10 bg-white/[0.025] text-ink-300 hover:border-white/25 hover:bg-white/[0.04]',
      ].join(' ')}
    >
      <div className="break-words text-[11px] font-medium uppercase leading-4 tracking-[0.08em]">{label}</div>
      <div className="mt-1 break-words text-[10px] leading-4 text-ink-500">{detail}</div>
    </button>
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
    <div className="mb-4 grid grid-cols-[2rem_minmax(0,1fr)] gap-3">
      <div className={['pt-0.5 text-[10px] uppercase tracking-[0.14em]', active ? 'text-accent-300' : 'text-ink-500'].join(' ')}>
        {idx}
      </div>
      <div className="min-w-0">
        <div className={['break-words text-xs font-medium leading-5', active ? 'text-ink-100' : 'text-ink-300'].join(' ')}>{title}</div>
        <div className="mt-1 break-words text-[11px] leading-5 text-ink-500">{body}</div>
      </div>
    </div>
  );
}
