import { encodeSecretAsync } from '../crypto';
import type { EncodeWorkerRequest, WorkerEvent, WorkerProgressEvent } from './protocol';

const cancelled = new Set<number>();

function post(event: WorkerEvent): void {
  self.postMessage(event);
}

self.onmessage = (event: MessageEvent<EncodeWorkerRequest>) => {
  const request = event.data;
  if (request.type === 'cancel') {
    cancelled.add(request.id);
    return;
  }

  void handleEncode(request);
};

async function handleEncode(request: Extract<EncodeWorkerRequest, { type: 'encode' }>): Promise<void> {
  const { id, plaintext, options } = request;
  cancelled.delete(id);
  try {
    const result = await encodeSecretAsync(plaintext, options, {
      onVdfProgress: (progress) => {
        if (cancelled.has(id)) throw new Error('encode cancelled');
        post({
          type: 'progress',
          id,
          stage: 'vdf-lock',
          done: progress.done.toString(),
          total: progress.total.toString(),
          shareIdx: progress.shareIdx,
          shareOrdinal: progress.shareOrdinal,
          shareTotal: progress.shareTotal,
        } satisfies WorkerProgressEvent);
      },
      onDecryptionProofProgress: (progress) => {
        if (cancelled.has(id)) throw new Error('encode cancelled');
        post({
          type: 'progress',
          id,
          stage: 'decryption-proof',
          done: progress.progress !== undefined ? String(Math.round(progress.progress * 100)) : '0',
          total: '100',
          status: progress.phase,
        } satisfies WorkerProgressEvent);
      },
    });
    if (cancelled.has(id)) return;
    post({ type: 'result', id, op: 'encode', result });
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
