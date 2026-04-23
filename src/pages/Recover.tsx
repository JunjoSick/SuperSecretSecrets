import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { QrScanner } from '../components/QrScanner';
import { inspectQr, type DecodeResult } from '../crypto';
import { KIND_HEADER, KIND_SHARE } from '../crypto/codec';

type ScannedQr = {
  payload: string;
  kind: 'header' | 'share' | 'unknown';
  bundleId?: string;
  detail?: string;
  chunkIdx?: number;
  chunkTotal?: number;
  shareIdx?: number;
  threshold?: number;
};

type ScanProgress = {
  ready: boolean;
  headerChunksSeen: number;
  headerChunksTotal: number | null;
  sharesSeen: number;
  threshold: number | null;
};

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export default function Recover() {
  const [scanned, setScanned] = useState<ScannedQr[]>([]);
  const [passphrase, setPassphrase] = useState('');
  const [decodeResult, setDecodeResult] = useState<DecodeResult | null>(null);
  const [decoding, setDecoding] = useState(false);
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
    setRevealed(false);
  };

  const payloads = useMemo(() => {
    return scanned.filter((s) => s.kind !== 'unknown').map((s) => s.payload);
  }, [scanned]);

  const scanProgress = useMemo(() => getScanProgress(scanned), [scanned]);

  useEffect(() => {
    workerRef.current?.terminate();
    decodeSeq.current++;
    setDecodeResult(null);
    setDecoding(false);
    setRevealed(false);
    setCopyOk(false);
  }, [payloads, passphrase]);

  useEffect(() => {
    return () => workerRef.current?.terminate();
  }, []);

  const decrypt = () => {
    if (!scanProgress.ready || decoding) return;
    workerRef.current?.terminate();
    const id = ++decodeSeq.current;
    const worker = new Worker(new URL('../workers/decode.worker.ts', import.meta.url), {
      type: 'module',
    });
    workerRef.current = worker;
    setDecoding(true);
    setDecodeResult(null);
    setRevealed(false);
    setCopyOk(false);

    worker.onmessage = (event: MessageEvent<{ id: number; result: DecodeResult }>) => {
      if (event.data.id !== decodeSeq.current) return;
      setDecodeResult(event.data.result);
      setDecoding(false);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };

    worker.onerror = () => {
      if (id !== decodeSeq.current) return;
      setDecodeResult({ status: 'error', error: 'decryption worker failed' });
      setDecoding(false);
      worker.terminate();
      if (workerRef.current === worker) workerRef.current = null;
    };

    worker.postMessage({ id, payloads, passphrase: passphrase || undefined });
  };

  const copy = async () => {
    if (decodeResult?.status !== 'ok' || !revealed) return;
    await navigator.clipboard.writeText(decodeResult.plaintext);
    setCopyOk(true);
    setTimeout(() => setCopyOk(false), 1500);
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
          <ScannedList items={scanned} onRemove={removeAt} />
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
          />

          <details className="card p-5 open:pb-6">
            <summary className="cursor-pointer text-sm font-medium text-ink-100">
              Passphrase (if used during encode)
            </summary>
            <input
              type="password"
              className="input mt-3"
              placeholder="leave blank unless encoded with one"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              autoComplete="off"
            />
          </details>

          {scanProgress.ready && decodeResult?.status !== 'ok' && (
            <div className="card border-accent-400/30 bg-accent-500/5 p-5">
              <h3 className="text-sm font-semibold text-ink-50">Ready to decrypt</h3>
              <p className="mt-2 text-xs leading-6 text-ink-300">
                Enough QR material has been scanned. Decrypt only when your screen is private.
              </p>
              <button className="btn-primary mt-4 w-full" onClick={decrypt} disabled={decoding}>
                {decoding ? 'Decrypting…' : 'Decrypt secret'}
              </button>
            </div>
          )}

          {decodeResult?.status === 'ok' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="card border-accent-400/30 bg-accent-500/5 p-5"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink-50">Secret recovered</h3>
                {revealed && (
                  <button className="btn-outline text-xs" onClick={copy}>
                    {copyOk ? 'Copied!' : 'Copy'}
                  </button>
                )}
              </div>
              {!revealed ? (
                <div className="mt-4 border border-accent-300/20 bg-black/30 p-4">
                  <p className="text-xs leading-6 text-ink-300">
                    The plaintext is decrypted locally and held in memory. Reveal it only when your
                    screen is private.
                  </p>
                  <button className="btn-primary mt-4 w-full" onClick={() => setRevealed(true)}>
                    Reveal plaintext
                  </button>
                </div>
              ) : (
                <pre className="mt-4 max-h-96 overflow-auto whitespace-pre-wrap break-words border border-accent-300/20 bg-black/40 p-3 font-mono text-sm text-ink-50 [animation:revealNoise_.38s_ease_both]">
                  {decodeResult.plaintext}
                </pre>
              )}
            </motion.div>
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

function Progress({
  progress,
  count,
  decoding,
  decrypted,
}: {
  progress: ScanProgress;
  count: number;
  decoding: boolean;
  decrypted: boolean;
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
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <p className="mt-2 text-sm text-ink-400">Decrypting locally…</p>
      </div>
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
  };
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
  onRemove,
}: {
  items: ScannedQr[];
  onRemove: (i: number) => void;
}) {
  if (items.length === 0) return null;
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
