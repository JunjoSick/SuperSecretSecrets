import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { QrScanner } from '../components/QrScanner';
import { WorkerProgressCard } from '../components/WorkerProgress';
import {
  createVaultDisclosure,
  encodeVaultDisclosure,
  inspectQr,
  type DecodeBundleResult,
  type DecryptionProofVerification,
  type DecodedShareMetadata,
  type VaultEntry,
} from '../crypto';
import { KIND_HEADER, KIND_SHARE, TLV_DECRYPTION_PROOF } from '../crypto/codec';
import { triggerDownload } from '../lib/zip';
import type { DecodeWorkerRequest, WorkerEvent, WorkerProgressEvent } from '../workers/protocol';

type ScannedQr = {
  payload: string;
  kind: 'header' | 'share' | 'unknown';
  bundleId?: string;
  detail?: string;
  chunkIdx?: number;
  chunkTotal?: number;
  shareIdx?: number;
  threshold?: number;
  passphraseProtected?: boolean;
  decryptionProof?: 'present' | 'missing';
};

type VaultBlobFile = {
  name: string;
  bytes: Uint8Array;
};

type SecretDecodeSuccess = Extract<DecodeBundleResult, { status: 'ok'; kind: 'secret' }>;
type VaultDecodeSuccess = Extract<DecodeBundleResult, { status: 'ok'; kind: 'vault' }>;

type ScanProgress = {
  ready: boolean;
  headerChunksSeen: number;
  headerChunksTotal: number | null;
  sharesSeen: number;
  threshold: number | null;
  passphraseRequired: boolean | null;
  decryptionProof: 'unknown' | 'present' | 'missing';
};

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

function isTextEntry(entry: VaultEntry): boolean {
  const type = entry.contentType?.toLowerCase() ?? '';
  const name = entry.name.toLowerCase();
  return (
    type.startsWith('text/') ||
    type.includes('json') ||
    name.endsWith('.txt') ||
    name.endsWith('.md') ||
    name.endsWith('.json') ||
    name.endsWith('.csv')
  );
}

function entryText(entry: VaultEntry): string | null {
  if (!isTextEntry(entry)) return null;
  try {
    return new TextDecoder().decode(entry.data);
  } catch {
    return null;
  }
}

function isImageEntry(entry: VaultEntry): boolean {
  return entry.contentType?.toLowerCase().startsWith('image/') ?? false;
}

function downloadVaultEntry(entry: VaultEntry): void {
  const copy = new Uint8Array(entry.data);
  triggerDownload(
    new Blob([copy.buffer as ArrayBuffer], {
      type: entry.contentType ?? 'application/octet-stream',
    }),
    entry.name || `${entry.id}.bin`,
  );
}

function disclosureFileName(entry: VaultEntry): string {
  const base = (entry.name || entry.id || 'vault-entry').replace(/[^A-Za-z0-9._-]+/g, '_');
  return `${base}.ssss-disclosure.json`;
}

export default function Recover() {
  const [scanned, setScanned] = useState<ScannedQr[]>([]);
  const [passphrase, setPassphrase] = useState('');
  const [vaultBlob, setVaultBlob] = useState<VaultBlobFile | null>(null);
  const [vaultErr, setVaultErr] = useState<string | null>(null);
  const [decodeResult, setDecodeResult] = useState<DecodeBundleResult | null>(null);
  const [decoding, setDecoding] = useState(false);
  const [decodeProgress, setDecodeProgress] = useState<WorkerProgressEvent | null>(null);
  const [revealed, setRevealed] = useState(false);
  const [copyOk, setCopyOk] = useState(false);
  const decodeSeq = useRef(0);
  const workerRef = useRef<Worker | null>(null);

  const addPayload = useCallback((raw: string) => {
    setScanned((prev) => {
      if (prev.some((p) => p.payload === raw)) return prev;
      try {
        const parsed = inspectQr(raw);
        const isHeader = parsed.kind === KIND_HEADER;
        const isShare = parsed.kind === KIND_SHARE;
        const hasDecryptionProof =
          isHeader && parsed.extensions?.some((extension) => extension.tagId === TLV_DECRYPTION_PROOF);
        return [
          ...prev,
          {
            payload: raw,
            kind: isHeader ? 'header' : isShare ? 'share' : 'unknown',
            bundleId: hex(parsed.bundleId),
            chunkIdx: isHeader ? parsed.chunkIdx : undefined,
            chunkTotal: isHeader ? parsed.chunkTotal : undefined,
            shareIdx: isShare ? parsed.shareIdx : undefined,
            threshold: isHeader || isShare ? parsed.t : undefined,
            passphraseProtected: isHeader ? parsed.flags.passphrase : undefined,
            decryptionProof: isHeader ? (hasDecryptionProof ? 'present' : 'missing') : undefined,
            detail: isHeader
              ? `header chunk ${parsed.chunkIdx + 1}/${parsed.chunkTotal}`
              : isShare
                ? `share #${parsed.shareIdx} (T=${parsed.t})`
                : 'unknown',
          },
        ];
      } catch (err) {
        const reason = err instanceof Error ? err.message : 'not a SuperSecretSecrets QR';
        return [...prev, { payload: raw, kind: 'unknown', detail: reason }];
      }
    });
  }, []);

  const removeAt = (i: number) =>
    setScanned((prev) => prev.filter((_, idx) => idx !== i));

  const clear = () => {
    setScanned([]);
    setPassphrase('');
    setVaultBlob(null);
    setVaultErr(null);
    setRevealed(false);
  };

  const payloads = useMemo(() => {
    return scanned.filter((s) => s.kind !== 'unknown').map((s) => s.payload);
  }, [scanned]);

  const scanProgress = useMemo(() => getScanProgress(scanned), [scanned]);
  const scannedMetadata = useMemo(
    () => (decodeResult && 'metadata' in decodeResult ? decodeResult.metadata : []),
    [decodeResult],
  );

  useEffect(() => {
    workerRef.current?.terminate();
    decodeSeq.current++;
    setDecodeResult(null);
    setDecoding(false);
    setDecodeProgress(null);
    setRevealed(false);
    setCopyOk(false);
  }, [payloads, passphrase, vaultBlob]);

  useEffect(() => {
    if (scanProgress.passphraseRequired === false && passphrase !== '') {
      setPassphrase('');
    }
  }, [passphrase, scanProgress.passphraseRequired]);

  useEffect(() => {
    return () => workerRef.current?.terminate();
  }, []);

  const decrypt = () => {
    if (!scanProgress.ready || decoding || (scanProgress.passphraseRequired && passphrase.length === 0)) return;
    workerRef.current?.terminate();
    const id = ++decodeSeq.current;
    const worker = new Worker(new URL('../workers/decode.worker.ts', import.meta.url), {
      type: 'module',
    });
    workerRef.current = worker;
    setDecoding(true);
    setDecodeResult(null);
    setDecodeProgress(null);
    setRevealed(false);
    setCopyOk(false);

    worker.onmessage = (event: MessageEvent<WorkerEvent>) => {
      if (event.data.id !== decodeSeq.current) return;
      if (event.data.type === 'progress') {
        setDecodeProgress(event.data);
        return;
      }
      if (event.data.type === 'result' && event.data.op === 'decode') {
        setDecodeResult(event.data.result);
      } else if (event.data.type === 'error') {
        setDecodeResult({ status: 'error', error: event.data.error });
      }
      setDecoding(false);
      setDecodeProgress(null);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };

    worker.onerror = () => {
      if (id !== decodeSeq.current) return;
      setDecodeResult({ status: 'error', error: 'decryption worker failed' });
      setDecoding(false);
      setDecodeProgress(null);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };

    worker.postMessage({
      type: 'decode',
      id,
      payloads,
      passphrase: passphrase || undefined,
      vaultBlob: vaultBlob?.bytes,
    } satisfies DecodeWorkerRequest);
  };

  const copy = async () => {
    if (decodeResult?.status !== 'ok' || decodeResult.kind !== 'secret' || !revealed) return;
    await navigator.clipboard.writeText(decodeResult.plaintext);
    setCopyOk(true);
    setTimeout(() => setCopyOk(false), 1500);
  };

  const importVaultBlob = async (file: File | null) => {
    setVaultErr(null);
    if (!file) return;
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      setVaultBlob({ name: file.name, bytes });
    } catch (e) {
      setVaultErr(e instanceof Error ? e.message : 'could not read vault blob');
      setVaultBlob(null);
    }
  };

  return (
    <div className="mx-auto max-w-7xl px-6 pb-24 pt-10">
      <header className="mb-6">
        <div className="mono-upper">02 · Ingest / reconstruct / reveal</div>
        <h1 className="mt-2 text-3xl font-medium tracking-tight text-ink-50">Feed shares through the lens.</h1>
        <p className="mt-1 text-sm text-ink-400">
          Gather any threshold-many share QR codes plus all header QR codes. Everything is
          decrypted locally.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1.35fr_390px]">
        <div className="flex flex-col gap-4">
          <QrScanner onPayload={addPayload} />
          <ScannedList items={scanned} metadata={scannedMetadata} onRemove={removeAt} />
          {scanned.length > 0 && (
            <div className="flex justify-end">
              <button className="btn-ghost text-xs" onClick={clear}>
                Clear all
              </button>
            </div>
          )}
        </div>

        <aside className="flex flex-col gap-4">
          <Progress
            progress={scanProgress}
            count={scanned.length}
            decoding={decoding}
            decrypted={decodeResult?.status === 'ok'}
            workerProgress={decodeProgress}
          />

          <AuditProofPanel progress={scanProgress} result={decodeResult} />

          <VaultBlobPanel
            vaultBlob={vaultBlob}
            error={vaultErr}
            onImport={importVaultBlob}
            onClear={() => {
              setVaultBlob(null);
              setVaultErr(null);
            }}
          />

          <PassphrasePanel
            required={scanProgress.passphraseRequired}
            passphrase={passphrase}
            setPassphrase={setPassphrase}
          />

          {scanProgress.ready && decodeResult?.status !== 'ok' && (
            <div className="card border-accent-400/30 bg-accent-500/5 p-5">
              <h3 className="text-sm font-semibold text-ink-50">Ready to decrypt</h3>
              <p className="mt-2 text-xs leading-6 text-ink-300">
                Enough QR material has been scanned. Decrypt only when your screen is private.
              </p>
              <button
                className="btn-primary mt-4 w-full"
                onClick={decrypt}
                disabled={decoding || (scanProgress.passphraseRequired === true && passphrase.length === 0)}
              >
                {decoding
                  ? 'Decrypting…'
                  : scanProgress.passphraseRequired === true && passphrase.length === 0
                    ? 'Enter passphrase'
                    : 'Decrypt / unlock'}
              </button>
            </div>
          )}

          {decodeResult?.status === 'ok' && decodeResult.kind === 'secret' && (
            <SecretRecovered
              result={decodeResult}
              revealed={revealed}
              copyOk={copyOk}
              onReveal={() => setRevealed(true)}
              onCopy={copy}
            />
          )}

          {decodeResult?.status === 'ok' && decodeResult.kind === 'vault' && (
            <VaultRecovered result={decodeResult} vaultBlobName={vaultBlob?.name} />
          )}

          {decodeResult?.status === 'error' && scanned.length > 0 && (
            <div className="card border-red-500/30 bg-red-500/5 p-4 text-sm text-red-200">
              {decodeResult.error}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function VaultBlobPanel({
  vaultBlob,
  error,
  onImport,
  onClear,
}: {
  vaultBlob: VaultBlobFile | null;
  error: string | null;
  onImport: (file: File | null) => void;
  onClear: () => void;
}) {
  return (
    <div className="card p-5">
      <div className="mono-upper">vault blob</div>
      {vaultBlob ? (
        <div className="mt-3 border border-amber-300/20 bg-amber-500/5 px-3 py-2 text-xs">
          <div className="truncate font-medium text-amber-100">{vaultBlob.name}</div>
          <div className="mt-1 font-mono text-ink-400">{formatBytes(vaultBlob.bytes.length)}</div>
          <button className="btn-ghost mt-3 text-xs" type="button" onClick={onClear}>
            Remove blob
          </button>
        </div>
      ) : (
        <>
          <p className="mt-2 text-xs leading-6 text-ink-400">
            Import the matching <span className="font-mono text-ink-200">.ssssvault</span> file for vault bundles.
          </p>
          <label className="btn-outline mt-3 cursor-pointer text-xs">
            Choose blob
            <input
              type="file"
              accept=".ssssvault,application/octet-stream"
              className="hidden"
              onChange={(e) => {
                void onImport(e.target.files?.[0] ?? null);
                e.currentTarget.value = '';
              }}
            />
          </label>
        </>
      )}
      {error && <div className="mt-3 text-xs text-red-300">{error}</div>}
    </div>
  );
}

function SecretRecovered({
  result,
  revealed,
  copyOk,
  onReveal,
  onCopy,
}: {
  result: SecretDecodeSuccess;
  revealed: boolean;
  copyOk: boolean;
  onReveal: () => void;
  onCopy: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className="card border-accent-400/30 bg-accent-500/5 p-5"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-ink-50">Secret recovered</h3>
        {revealed && (
          <button className="btn-outline text-xs" onClick={onCopy}>
            {copyOk ? 'Copied!' : 'Copy'}
          </button>
        )}
      </div>
      {!revealed ? (
        <div className="mt-4 border border-accent-300/20 bg-black/30 p-4">
          <p className="text-xs leading-6 text-ink-300">
            The plaintext is decrypted locally and held in memory. Reveal it only when your screen is private.
          </p>
          <button className="btn-primary mt-4 w-full" onClick={onReveal}>
            Reveal plaintext
          </button>
        </div>
      ) : (
        <pre className="mt-4 max-h-96 overflow-auto whitespace-pre-wrap break-words border border-accent-300/20 bg-black/40 p-3 font-mono text-sm text-ink-50 [animation:revealNoise_.38s_ease_both]">
          {result.plaintext}
        </pre>
      )}
    </motion.div>
  );
}

function VaultRecovered({
  result,
  vaultBlobName,
}: {
  result: VaultDecodeSuccess;
  vaultBlobName?: string;
}) {
  const [revealed, setRevealed] = useState<Set<string>>(() => new Set());
  const [disclosureErr, setDisclosureErr] = useState<string | null>(null);
  const toggleReveal = (id: string) => {
    setRevealed((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };
  const disclose = (entry: VaultEntry) => {
    if (!result.vault || !result.vaultTreeRoot) return;
    const disclosure = createVaultDisclosure(result.vault, entry.id, {
      bundleId: result.bundleId,
      vaultId: result.vaultId,
      root: result.vaultTreeRoot,
    });
    if ('status' in disclosure) {
      setDisclosureErr(disclosure.error);
      return;
    }
    setDisclosureErr(null);
    triggerDownload(
      new Blob([encodeVaultDisclosure(disclosure)], { type: 'application/json' }),
      disclosureFileName(entry),
    );
  };

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.98 }}
      animate={{ opacity: 1, scale: 1 }}
      className="card border-amber-300/30 bg-amber-500/5 p-5"
    >
      <div className="flex items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-ink-50">Vault unlocked</h3>
          {vaultBlobName && <div className="mt-1 truncate font-mono text-[10px] text-ink-400">{vaultBlobName}</div>}
        </div>
        <span className="chip border-amber-300/30 text-amber-200">
          {result.vault ? `${result.vault.entries.length} entries` : 'key ready'}
        </span>
      </div>

      {!result.vault ? (
        <div className="mt-4 border border-amber-300/20 bg-black/30 p-4 text-xs leading-6 text-ink-300">
          Vault key recovered. Import the matching <span className="font-mono text-ink-200">.ssssvault</span> blob to reveal entries.
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          {disclosureErr && (
            <div className="border border-red-500/30 bg-red-500/5 px-3 py-2 text-xs text-red-200">
              {disclosureErr}
            </div>
          )}
          {result.vault.entries.map((entry) => {
            const text = entryText(entry);
            const image = isImageEntry(entry);
            const isRevealed = revealed.has(entry.id);
            return (
              <div key={entry.id} className="border border-amber-300/20 bg-black/25 p-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-medium text-ink-100">{entry.name}</div>
                    <div className="mt-1 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-500">
                      <span>{formatBytes(entry.data.length)}</span>
                      {entry.contentType && <span>{entry.contentType}</span>}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-wrap justify-end gap-2">
                    {text !== null && (
                      <button className="btn-outline px-3 py-1.5 text-[10px]" onClick={() => toggleReveal(entry.id)}>
                        {isRevealed ? 'Hide' : 'Reveal'}
                      </button>
                    )}
                    <button className="btn-primary px-3 py-1.5 text-[10px]" onClick={() => downloadVaultEntry(entry)}>
                      Download
                    </button>
                    {result.vaultTreeRoot && (
                      <button className="btn-outline px-3 py-1.5 text-[10px]" onClick={() => disclose(entry)}>
                        Disclose
                      </button>
                    )}
                  </div>
                </div>
                {text !== null && isRevealed && (
                  <pre className="mt-3 max-h-72 overflow-auto whitespace-pre-wrap break-words border border-amber-300/20 bg-black/40 p-3 font-mono text-xs text-ink-50 [animation:revealNoise_.38s_ease_both]">
                    {text}
                  </pre>
                )}
                {image && <VaultImagePreview entry={entry} />}
              </div>
            );
          })}
        </div>
      )}
    </motion.div>
  );
}

function VaultImagePreview({ entry }: { entry: VaultEntry }) {
  const [url, setUrl] = useState<string | null>(null);

  useEffect(() => {
    const nextUrl = URL.createObjectURL(
      new Blob([entry.data.slice().buffer as ArrayBuffer], {
        type: entry.contentType ?? 'application/octet-stream',
      }),
    );
    setUrl(nextUrl);
    return () => URL.revokeObjectURL(nextUrl);
  }, [entry]);

  if (!url) return null;
  return (
    <div className="mt-3 border border-amber-300/20 bg-black/35 p-2">
      <img
        src={url}
        alt={entry.name}
        className="max-h-80 w-full object-contain"
      />
    </div>
  );
}

function Progress({
  progress,
  count,
  decoding,
  decrypted,
  workerProgress,
}: {
  progress: ScanProgress;
  count: number;
  decoding: boolean;
  decrypted: boolean;
  workerProgress: WorkerProgressEvent | null;
}) {
  if (count === 0) {
    return (
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <p className="mt-2 text-sm text-ink-400">Start scanning QR codes.</p>
      </div>
    );
  }
  if (decoding) {
    return (
      <WorkerProgressCard
        title="Decrypting bundle"
        fallback="Decrypting locally."
        progress={workerProgress}
      />
    );
  }
  if (!progress.ready) {
    const chunks =
      progress.headerChunksTotal !== null
        ? `${progress.headerChunksSeen} / ${progress.headerChunksTotal}`
        : `${progress.headerChunksSeen} / ?`;
    const shares =
      progress.threshold !== null
        ? `${Math.min(progress.sharesSeen, progress.threshold)} / ${progress.threshold}`
        : `${progress.sharesSeen} / ?`;
    return (
      <div className="card p-5">
        <div className="mono-upper">quorum</div>
        <div className="grid place-items-center py-6">
          <ProgressRing current={progress.threshold !== null ? Math.min(progress.sharesSeen, progress.threshold) : 0} total={progress.threshold ?? 3} />
        </div>
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
          <StatusRow label="Header" text={chunks} />
          <StatusRow label="Shares" text={shares} />
        </div>
      </div>
    );
  }
  return (
    <div className="card p-5">
      <div className="mono-upper">quorum</div>
      <div className="grid place-items-center py-6">
        <ProgressRing current={progress.threshold ?? progress.sharesSeen} total={progress.threshold ?? progress.sharesSeen} />
      </div>
      <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
      <p className="mt-2 text-sm text-accent-200">
        ● quorum reached — {decrypted ? 'secret decrypted.' : 'ready to decrypt.'}
      </p>
    </div>
  );
}

function getScanProgress(scanned: ScannedQr[]): ScanProgress {
  const valid = scanned.filter((s) => s.kind !== 'unknown' && s.bundleId);
  if (valid.length === 0) {
    return {
      ready: false,
      headerChunksSeen: 0,
      headerChunksTotal: null,
      sharesSeen: 0,
      threshold: null,
      passphraseRequired: null,
      decryptionProof: 'unknown',
    };
  }

  const groups = new Map<string, ScannedQr[]>();
  for (const item of valid) {
    const key = item.bundleId!;
    groups.set(key, [...(groups.get(key) ?? []), item]);
  }

  let best: ScannedQr[] = [];
  for (const group of groups.values()) {
    if (group.length > best.length) best = group;
  }

  const headerIndexes = new Set(
    best
      .filter((s) => s.kind === 'header' && s.chunkIdx !== undefined)
      .map((s) => s.chunkIdx!),
  );
  const shareIndexes = new Set(
    best
      .filter((s) => s.kind === 'share' && s.shareIdx !== undefined)
      .map((s) => s.shareIdx!),
  );
  const headerChunksTotal =
    best.find((s) => s.kind === 'header' && s.chunkTotal !== undefined)?.chunkTotal ?? null;
  const threshold = best.find((s) => s.threshold !== undefined)?.threshold ?? null;
  const passphraseRequired =
    best.find((s) => s.kind === 'header' && s.passphraseProtected !== undefined)
      ?.passphraseProtected ?? null;
  const headerZero = best.find((s) => s.kind === 'header' && s.chunkIdx === 0);
  const decryptionProof = headerZero?.decryptionProof ?? 'unknown';

  return {
    ready:
      headerChunksTotal !== null &&
      threshold !== null &&
      headerIndexes.size >= headerChunksTotal &&
      shareIndexes.size >= threshold,
    headerChunksSeen: headerIndexes.size,
    headerChunksTotal,
    sharesSeen: shareIndexes.size,
    threshold,
    passphraseRequired,
    decryptionProof,
  };
}

function AuditProofPanel({
  progress,
  result,
}: {
  progress: ScanProgress;
  result: DecodeBundleResult | null;
}) {
  const status = auditProofStatus(progress, result);
  const style = auditProofStyle(status.tone);
  return (
    <div className={['card p-5', style.card].join(' ')}>
      <div className={['mono-upper', style.kicker].join(' ')}>auditor proof</div>
      <div className="mt-3 flex flex-wrap items-start justify-between gap-3">
        <h3 className="min-w-0 text-sm font-semibold leading-5 text-ink-100">{status.title}</h3>
        <span className={['chip', style.chip].join(' ')}>{status.chip}</span>
      </div>
      <p className="mt-2 text-xs leading-6 text-ink-400">{status.body}</p>
    </div>
  );
}

function auditProofStatus(
  progress: ScanProgress,
  result: DecodeBundleResult | null,
): { tone: 'neutral' | 'ok' | 'warn' | 'bad'; chip: string; title: string; body: string } {
  if (result?.status === 'ok') {
    return decryptionProofStatus(result.decryptionProof);
  }
  if (result?.status === 'error' && result.error.toLowerCase().includes('decryption proof')) {
    return {
      tone: 'bad',
      chip: 'failed',
      title: 'Proof claim failed',
      body: result.error,
    };
  }
  if (progress.decryptionProof === 'present') {
    return {
      tone: 'warn',
      chip: 'pending',
      title: 'Proof claim detected',
      body: 'Proof found; verification will run before the recovered secret is trusted.',
    };
  }
  if (progress.decryptionProof === 'missing') {
    return {
      tone: 'neutral',
      chip: 'missing',
      title: 'No proof TLV',
      body: 'No auditor decryption proof is present. Recovery security is unchanged.',
    };
  }
  return {
    tone: 'neutral',
    chip: 'unknown',
    title: 'Header needed',
    body: 'Scan header chunk 1 to inspect bundle-level proof status.',
  };
}

function decryptionProofStatus(
  proof: DecryptionProofVerification | undefined,
): { tone: 'neutral' | 'ok' | 'warn' | 'bad'; chip: string; title: string; body: string } {
  if (!proof) {
    return {
      tone: 'neutral',
      chip: 'missing',
      title: 'No proof TLV',
      body: 'Recovery succeeded without an auditor decryption proof.',
    };
  }
  switch (proof.status) {
    case 'verified':
      return {
        tone: 'ok',
        chip: 'verified',
        title: 'Verified auditor decryption proof',
        body: `Verified: this v3 vault-root bundle matches the registered proof relation, transcript digest, and published Poseidon2 proof-facing commitments. The current Halo2 milestone proves the vault-root commitment and transcript binding.${
          proof.label ? ` Verifier: ${proof.label}.` : ''
        }`,
      };
    case 'unsupported':
      return {
        tone: 'warn',
        chip: 'unsupported',
        title: 'Proof verifier unavailable',
        body: `This proof relation or verifier artifact is not supported by this app. Scheme ${proof.schemeId} is present.`,
      };
    case 'invalid':
    case 'tampered':
    case 'malformed':
      return {
        tone: 'bad',
        chip: proof.status,
        title: 'Invalid auditor decryption proof',
        body: `The proof claim is malformed, tampered, or does not match this bundle. ${proof.reason}`,
      };
  }
}

function auditProofStyle(tone: 'neutral' | 'ok' | 'warn' | 'bad'): { card: string; chip: string; kicker: string } {
  switch (tone) {
    case 'ok':
      return {
        card: 'border-emerald-400/30 bg-emerald-500/5',
        chip: 'border-emerald-400/30 text-emerald-200',
        kicker: 'text-emerald-300',
      };
    case 'warn':
      return {
        card: 'border-amber-300/30 bg-amber-500/5',
        chip: 'border-amber-300/30 text-amber-200',
        kicker: 'text-amber-300',
      };
    case 'bad':
      return {
        card: 'border-red-500/30 bg-red-500/5',
        chip: 'border-red-500/30 text-red-300',
        kicker: 'text-red-300',
      };
    case 'neutral':
      return {
        card: 'border-white/10 bg-white/[0.02]',
        chip: 'border-white/10 text-ink-400',
        kicker: 'text-ink-500',
      };
  }
}

function PassphrasePanel({
  required,
  passphrase,
  setPassphrase,
}: {
  required: boolean | null;
  passphrase: string;
  setPassphrase: (passphrase: string) => void;
}) {
  if (required === null) {
    return (
      <div className="card p-5">
        <div className="mono-upper">passphrase</div>
        <p className="mt-2 text-xs leading-6 text-ink-400">
          Scan a header QR to detect whether this bundle needs a passphrase.
        </p>
      </div>
    );
  }

  if (!required) {
    return (
      <div className="card border-white/10 bg-white/[0.02] p-5">
        <div className="mono-upper">passphrase</div>
        <p className="mt-2 text-xs leading-6 text-ink-400">
          This bundle was encoded without a passphrase.
        </p>
      </div>
    );
  }

  return (
    <div className="card border-amber-300/30 bg-amber-500/5 p-5">
      <div className="mono-upper text-amber-300">passphrase required</div>
      <p className="mt-2 text-xs leading-6 text-ink-300">
        This bundle was encoded with the optional Argon2id passphrase layer.
      </p>
      <input
        type="password"
        className="input mt-3"
        placeholder="enter passphrase"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
        autoComplete="off"
      />
    </div>
  );
}

function StatusRow({ label, text }: { label: string; text: string }) {
  return (
    <div className="border border-white/10 bg-white/[0.035] px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-ink-400">{label}</div>
      <div className="mt-0.5 font-mono text-ink-100">{text}</div>
    </div>
  );
}

function ProgressRing({ current, total }: { current: number; total: number }) {
  const size = 190;
  const stroke = 6;
  const radius = (size - stroke) / 2;
  const safeTotal = Math.max(total, 1);
  const gap = 0.04;
  const segment = (2 * Math.PI - gap * safeTotal) / safeTotal;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true">
      {Array.from({ length: safeTotal }).map((_, i) => {
        const start = -Math.PI / 2 + i * (segment + gap);
        const end = start + segment;
        const active = i < current;
        const x1 = size / 2 + radius * Math.cos(start);
        const y1 = size / 2 + radius * Math.sin(start);
        const x2 = size / 2 + radius * Math.cos(end);
        const y2 = size / 2 + radius * Math.sin(end);
        const largeArc = end - start > Math.PI ? 1 : 0;
        return (
          <path
            key={i}
            d={`M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2}`}
            fill="none"
            stroke={active ? 'rgb(93 220 255)' : 'rgb(255 255 255 / 0.12)'}
            strokeWidth={stroke}
          />
        );
      })}
      <text
        x={size / 2}
        y={size / 2 - 4}
        textAnchor="middle"
        fontSize="42"
        fontWeight="500"
        fill={current >= safeTotal ? 'rgb(150 235 255)' : 'rgb(237 241 244)'}
      >
        {current}
      </text>
      <text
        x={size / 2}
        y={size / 2 + 22}
        textAnchor="middle"
        fontSize="11"
        fill="rgb(101 119 128)"
        letterSpacing="0.2em"
      >
        OF {safeTotal}
      </text>
    </svg>
  );
}

function ScannedList({
  items,
  metadata,
  onRemove,
}: {
  items: ScannedQr[];
  metadata: DecodedShareMetadata[];
  onRemove: (i: number) => void;
}) {
  if (items.length === 0) return null;
  const metadataByShare = new Map(metadata.map((entry) => [entry.shareIdx, entry]));
  return (
    <div className="card p-4">
      <div className="mono-upper mb-3">
        Scanned ({items.length})
      </div>
      <ul className="space-y-1.5">
        {items.map((it, i) => (
          <li
            key={i}
            className="flex items-center justify-between gap-3 border border-white/10 bg-white/[0.035] px-3 py-2 text-xs [animation:tileIn_.28s_ease_both]"
          >
            <div className="flex min-w-0 items-center gap-2">
              <span
                className={[
                  'chip',
                  it.kind === 'header'
                    ? 'border-accent-400/30 text-accent-200'
                    : it.kind === 'share'
                      ? 'text-ink-100'
                      : 'border-red-500/30 text-red-300',
                ].join(' ')}
              >
                {it.kind}
              </span>
              <span className="truncate text-ink-200">{it.detail}</span>
              {it.bundleId && (
                <span className="truncate font-mono text-[10px] text-ink-400">
                  bundle {it.bundleId.slice(0, 8)}…
                </span>
              )}
              {it.kind === 'share' && typeof it.shareIdx === 'number' && metadataByShare.has(it.shareIdx) && (
                <span className={zkChipClass(metadataByShare.get(it.shareIdx)!.zkVerification)}>
                  {zkChipLabel(metadataByShare.get(it.shareIdx)!.zkVerification)}
                </span>
              )}
            </div>
            <button
              className="text-ink-400 hover:text-red-300"
              onClick={() => onRemove(i)}
              aria-label="Remove"
            >
              ✕
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

function zkChipLabel(status: DecodedShareMetadata['zkVerification']): string {
  switch (status) {
    case 'verified':
      return 'ZK OK';
    case 'tampered':
      return 'ZK BAD';
    case 'unverified':
      return 'ZK ?';
  }
}

function zkChipClass(status: DecodedShareMetadata['zkVerification']): string {
  const base = 'chip shrink-0';
  switch (status) {
    case 'verified':
      return `${base} border-emerald-400/30 text-emerald-200`;
    case 'tampered':
      return `${base} border-red-500/30 text-red-300`;
    case 'unverified':
      return `${base} border-white/10 text-ink-400`;
  }
}
