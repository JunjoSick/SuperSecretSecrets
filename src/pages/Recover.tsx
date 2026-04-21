import { useCallback, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { QrScanner } from '../components/QrScanner';
import { decodeSecret, inspectQr, type DecodeResult } from '../crypto';
import { KIND_HEADER, KIND_SHARE } from '../crypto/codec';

type ScannedQr = {
  payload: string;
  kind: 'header' | 'share' | 'unknown';
  bundleId?: string;
  detail?: string;
};

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

export default function Recover() {
  const [scanned, setScanned] = useState<ScannedQr[]>([]);
  const [passphrase, setPassphrase] = useState('');
  const [revealed, setRevealed] = useState(false);
  const [copyOk, setCopyOk] = useState(false);

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
    setRevealed(false);
  };

  const decodeResult: DecodeResult = useMemo(() => {
    const payloads = scanned.filter((s) => s.kind !== 'unknown').map((s) => s.payload);
    return decodeSecret(payloads, passphrase || undefined);
  }, [scanned, passphrase]);

  const copy = async () => {
    if (decodeResult.status !== 'ok') return;
    await navigator.clipboard.writeText(decodeResult.plaintext);
    setCopyOk(true);
    setTimeout(() => setCopyOk(false), 1500);
  };

  return (
    <div className="mx-auto max-w-6xl px-6 pb-24 pt-10">
      <header className="mb-6">
        <h1 className="text-3xl font-bold tracking-tight text-ink-50">Recover a secret</h1>
        <p className="mt-1 text-sm text-ink-400">
          Gather any threshold-many share QR codes plus all header QR codes. Everything is
          decrypted locally.
        </p>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1fr_380px]">
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
          <Progress result={decodeResult} count={scanned.length} />

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

          {decodeResult.status === 'ok' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.98 }}
              animate={{ opacity: 1, scale: 1 }}
              className="card border-accent-400/30 bg-accent-500/5 p-5"
            >
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-semibold text-ink-50">Secret recovered</h3>
                {revealed && (
                  <div className="flex items-center gap-2">
                    <button className="btn-outline text-xs" onClick={copy}>
                      {copyOk ? 'Copied!' : 'Copy'}
                    </button>
                    <button className="btn-ghost text-xs" onClick={() => setRevealed(false)}>
                      Hide
                    </button>
                  </div>
                )}
              </div>
              {!revealed ? (
                <button
                  className="btn-primary mt-4 w-full"
                  onClick={() => setRevealed(true)}
                >
                  Reveal plaintext
                </button>
              ) : (
                <pre className="mt-4 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg bg-black/40 p-3 font-mono text-sm text-ink-50">
                  {decodeResult.plaintext}
                </pre>
              )}
            </motion.div>
          )}

          {decodeResult.status === 'error' && scanned.length > 0 && (
            <div className="card border-red-500/30 bg-red-500/5 p-4 text-sm text-red-200">
              {decodeResult.error}
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function Progress({ result, count }: { result: DecodeResult; count: number }) {
  if (count === 0) {
    return (
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <p className="mt-2 text-sm text-ink-400">Start scanning QR codes.</p>
      </div>
    );
  }
  if (result.status === 'need-more') {
    const chunks =
      result.headerChunksTotal !== null
        ? `${result.headerChunksSeen} / ${result.headerChunksTotal}`
        : `${result.headerChunksSeen} / ?`;
    const shares =
      result.threshold !== null
        ? `${Math.min(result.sharesSeen, result.threshold)} / ${result.threshold}`
        : `${result.sharesSeen} / ?`;
    return (
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <div className="mt-3 grid grid-cols-2 gap-3 text-sm">
          <StatusRow label="Header" text={chunks} />
          <StatusRow label="Shares" text={shares} />
        </div>
      </div>
    );
  }
  if (result.status === 'ok') {
    return (
      <div className="card p-5">
        <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
        <p className="mt-2 text-sm text-accent-200">✓ Enough scanned — secret is ready.</p>
      </div>
    );
  }
  return (
    <div className="card p-5">
      <h3 className="text-sm font-semibold text-ink-100">Progress</h3>
      <p className="mt-2 text-sm text-red-300">{result.error}</p>
    </div>
  );
}

function StatusRow({ label, text }: { label: string; text: string }) {
  return (
    <div className="rounded-lg bg-white/5 px-3 py-2">
      <div className="text-[10px] uppercase tracking-wider text-ink-400">{label}</div>
      <div className="mt-0.5 font-mono text-ink-100">{text}</div>
    </div>
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
      <div className="mb-2 text-xs font-medium text-ink-300">
        Scanned ({items.length})
      </div>
      <ul className="space-y-1.5">
        {items.map((it, i) => (
          <li
            key={i}
            className="flex items-center justify-between gap-3 rounded-lg bg-white/5 px-3 py-1.5 text-xs"
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
