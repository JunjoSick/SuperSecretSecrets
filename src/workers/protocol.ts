import type { DecodeBundleResult, EncodedBundle, EncodeOptions } from '../crypto';

export type WorkerProgressStage = 'vdf-lock' | 'vdf-unlock' | 'zk-verify' | 'decryption-proof';

export type WorkerProgressEvent = {
  type: 'progress';
  id: number;
  stage: WorkerProgressStage;
  done: string;
  total: string;
  shareIdx?: number;
  shareOrdinal?: number;
  shareTotal?: number;
  label?: string;
  status?:
    | 'initializing'
    | 'witness'
    | 'proving'
    | 'local-verifying'
    | 'zeroizing'
    | 'done'
    | 'verifying'
    | 'verified'
    | 'tampered'
    | 'unsupported'
    | 'failed';
};

export type WorkerResultEvent =
  | {
      type: 'result';
      id: number;
      op: 'encode';
      result: EncodedBundle;
    }
  | {
      type: 'result';
      id: number;
      op: 'decode';
      result: DecodeBundleResult;
    };

export type WorkerErrorEvent = {
  type: 'error';
  id: number;
  error: string;
};

export type WorkerEvent = WorkerProgressEvent | WorkerResultEvent | WorkerErrorEvent;

export type EncodeWorkerRequest =
  | {
      type: 'encode';
      id: number;
      plaintext: string;
      options: Partial<EncodeOptions>;
    }
  | {
      type: 'cancel';
      id: number;
    };

export type DecodeWorkerRequest =
  | {
      type: 'decode';
      id: number;
      payloads: string[];
      passphrase?: string;
      vaultBlob?: Uint8Array;
    }
  | {
      type: 'cancel';
      id: number;
    };
