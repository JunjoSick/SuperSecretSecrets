import type { WorkerProgressEvent } from '../workers/protocol';

type Props = {
  title: string;
  fallback: string;
  progress: WorkerProgressEvent | null;
};

export function WorkerProgressCard({ title, fallback, progress }: Props) {
  const percent = progress ? progressPercent(progress) : 0;
  return (
    <div className="card p-5">
      <div className="mono-upper">worker</div>
      <h3 className="mt-2 text-sm font-semibold text-ink-100">{title}</h3>
      <p className="mt-2 text-xs leading-6 text-ink-400">
        {progress ? progressLabel(progress) : fallback}
      </p>
      {progress && (
        <div className="mt-4">
          <div className="h-2 overflow-hidden border border-white/10 bg-black/30">
            <div className="h-full bg-accent-300 transition-[width]" style={{ width: `${percent}%` }} />
          </div>
          <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-ink-500">
            <span>{progress.done}</span>
            <span>{Math.round(percent)}%</span>
            <span>{progress.total}</span>
          </div>
        </div>
      )}
    </div>
  );
}

function progressPercent(progress: WorkerProgressEvent): number {
  const total = BigInt(progress.total);
  if (total <= 0n) return 0;
  const done = BigInt(progress.done);
  const clamped = done < 0n ? 0n : done > total ? total : done;
  return Number((clamped * 1000n) / total) / 10;
}

function progressLabel(progress: WorkerProgressEvent): string {
  if (progress.stage === 'decryption-proof') {
    const phase = progress.status ?? 'proving';
    switch (phase) {
      case 'initializing':
        return 'Preparing the decryption proof backend.';
      case 'witness':
        return 'Preparing proof witness material.';
      case 'proving':
        return 'Generating the auditor decryption proof.';
      case 'local-verifying':
      case 'verifying':
        return 'Checking the proof before it is trusted.';
      case 'zeroizing':
        return 'Clearing temporary witness buffers.';
      case 'done':
      case 'verified':
        return 'Decryption proof verified.';
      case 'unsupported':
        return 'Proof relation is not supported by this build.';
      case 'failed':
        return 'Decryption proof failed.';
      case 'tampered':
        return 'Proof claim does not match this bundle.';
    }
  }
  if (progress.stage === 'vdf-lock') {
    const share = progress.shareIdx !== undefined ? ` #${progress.shareIdx}` : '';
    const ordinal =
      progress.shareOrdinal !== undefined && progress.shareTotal !== undefined
        ? ` (${progress.shareOrdinal}/${progress.shareTotal})`
        : '';
    return `Computing VDF lock for share${share}${ordinal}.`;
  }
  if (progress.stage === 'vdf-unlock') {
    const share = progress.shareIdx !== undefined ? ` #${progress.shareIdx}` : '';
    const ordinal =
      progress.shareOrdinal !== undefined && progress.shareTotal !== undefined
        ? ` (${progress.shareOrdinal}/${progress.shareTotal})`
        : '';
    return `Computing VDF unlock for share${share}${ordinal}.`;
  }
  const label = progress.label ? progress.label.replace('-', ' ') : 'commitment';
  const status = progress.status ?? 'verifying';
  return `ZK ${label}: ${status}.`;
}
