import { decodeBundleAsync } from '../crypto';
import type { DecodeWorkerRequest, WorkerEvent, WorkerProgressEvent } from './protocol';

const cancelled = new Set<number>();

function post(event: WorkerEvent): void {
  self.postMessage(event);
}

self.onmessage = (event: MessageEvent<DecodeWorkerRequest>) => {
  const request = event.data;
  if (request.type === 'cancel') {
    cancelled.add(request.id);
    return;
  }

  void handleDecode(request);
};

async function handleDecode(request: Extract<DecodeWorkerRequest, { type: 'decode' }>): Promise<void> {
  const { id, payloads, passphrase, vaultBlob } = request;
  cancelled.delete(id);
  try {
    const result = await decodeBundleAsync(payloads, {
      passphrase,
      vaultBlob,
      onVdfProgress: (progress) => {
        if (cancelled.has(id)) throw new Error('decode cancelled');
        post({
          type: 'progress',
          id,
          stage: 'vdf-unlock',
          done: progress.done.toString(),
          total: progress.total.toString(),
          shareIdx: progress.shareIdx,
          shareOrdinal: progress.shareOrdinal,
          shareTotal: progress.shareTotal,
        } satisfies WorkerProgressEvent);
      },
      onZkProgress: (progress) => {
        if (cancelled.has(id)) throw new Error('decode cancelled');
        post({
          type: 'progress',
          id,
          stage: 'zk-verify',
          done: progress.done.toString(),
          total: progress.total.toString(),
          label: progress.check,
          status: progress.status,
        } satisfies WorkerProgressEvent);
      },
    });
    if (cancelled.has(id)) return;
    post({ type: 'result', id, op: 'decode', result });
  } catch (error) {
    post({
      type: 'error',
      id,
      error: error instanceof Error ? error.message : String(error),
    });
  } finally {
    cancelled.delete(id);
  }
}
