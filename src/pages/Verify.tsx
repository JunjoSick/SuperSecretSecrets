import { useState } from 'react';
import {
  decodeVaultDisclosure,
  verifyVaultDisclosure,
  type VaultDisclosure,
} from '../crypto';
import { triggerDownload } from '../lib/zip';

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function normalizeHex(value: string): string {
  return value.trim().toLowerCase().replace(/^0x/, '').replace(/\s+/g, '');
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

function downloadEntry(disclosure: VaultDisclosure): void {
  const entry = disclosure.entry;
  triggerDownload(
    new Blob([entry.data.slice().buffer as ArrayBuffer], {
      type: entry.contentType ?? 'application/octet-stream',
    }),
    entry.name || `${entry.id}.bin`,
  );
}

export default function Verify() {
  const [disclosure, setDisclosure] = useState<VaultDisclosure | null>(null);
  const [expectedRoot, setExpectedRoot] = useState('');
  const [error, setError] = useState<string | null>(null);

  const importDisclosure = async (file: File | null) => {
    setError(null);
    setDisclosure(null);
    if (!file) return;
    try {
      setDisclosure(decodeVaultDisclosure(new Uint8Array(await file.arrayBuffer())));
    } catch (e) {
      setError(e instanceof Error ? e.message : 'could not read disclosure');
    }
  };

  const proofOk = disclosure ? verifyVaultDisclosure(disclosure) : false;
  const actualRoot = disclosure ? hex(disclosure.root) : '';
  const expected = normalizeHex(expectedRoot);
  const rootOk = !expected || expected === actualRoot;
  const verified = !!disclosure && proofOk && rootOk;

  return (
    <div className="mx-auto max-w-5xl px-6 pb-24 pt-10">
      <header className="mb-6">
        <div className="mono-upper">03 · disclose / verify</div>
        <h1 className="mt-2 text-3xl font-medium tracking-tight text-ink-50">Verify a vault disclosure.</h1>
      </header>

      <div className="grid gap-6 lg:grid-cols-[1fr_360px]">
        <section className="card p-5">
          <div className="mono-upper">disclosure json</div>
          <label className="btn-outline mt-4 inline-flex cursor-pointer text-xs">
            Choose disclosure
            <input
              type="file"
              accept=".json,application/json"
              className="hidden"
              onChange={(e) => {
                void importDisclosure(e.target.files?.[0] ?? null);
                e.currentTarget.value = '';
              }}
            />
          </label>
          <label className="mt-5 block">
            <span className="mb-1.5 block text-xs font-medium text-ink-300">Expected vault-tree root</span>
            <input
              className="input font-mono text-xs"
              placeholder="optional hex root"
              value={expectedRoot}
              onChange={(e) => setExpectedRoot(e.target.value)}
              spellCheck={false}
            />
          </label>
          {error && <div className="mt-4 border border-red-500/30 bg-red-500/5 p-3 text-sm text-red-200">{error}</div>}
        </section>

        <aside className="card p-5">
          <div className="mono-upper">result</div>
          {!disclosure ? (
            <p className="mt-3 text-sm text-ink-400">No disclosure loaded.</p>
          ) : (
            <div className="mt-4 space-y-4">
              <div
                className={[
                  'border px-3 py-2 text-sm',
                  verified
                    ? 'border-emerald-400/30 bg-emerald-500/5 text-emerald-100'
                    : 'border-red-500/30 bg-red-500/5 text-red-200',
                ].join(' ')}
              >
                {verified ? 'Disclosure verified' : 'Disclosure failed verification'}
              </div>

              <div className="space-y-2 text-xs">
                <StatusRow label="Proof" value={proofOk ? 'valid' : 'invalid'} ok={proofOk} />
                <StatusRow label="Root" value={rootOk ? 'matched' : 'mismatch'} ok={rootOk} />
              </div>

              <div className="border border-white/10 bg-white/[0.03] p-3">
                <div className="truncate text-sm font-medium text-ink-100">{disclosure.entry.name}</div>
                <div className="mt-1 flex flex-wrap gap-2 text-[10px] uppercase tracking-[0.14em] text-ink-500">
                  <span>{formatBytes(disclosure.entry.data.length)}</span>
                  {disclosure.entry.contentType && <span>{disclosure.entry.contentType}</span>}
                </div>
                <button className="btn-primary mt-3 w-full text-xs" onClick={() => downloadEntry(disclosure)}>
                  Download entry
                </button>
              </div>

              <div className="break-all font-mono text-[10px] leading-5 text-ink-500">
                {actualRoot}
              </div>
            </div>
          )}
        </aside>
      </div>
    </div>
  );
}

function StatusRow({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return (
    <div className="flex items-center justify-between border border-white/10 bg-white/[0.03] px-3 py-2">
      <span className="text-ink-400">{label}</span>
      <span className={ok ? 'text-emerald-200' : 'text-red-300'}>{value}</span>
    </div>
  );
}
