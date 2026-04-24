import { decodeBundle, type DecodeBundleResult } from '../crypto';

type DecodeRequest = {
  id: number;
  payloads: string[];
  passphrase?: string;
  vaultBlob?: Uint8Array;
};

type DecodeResponse = {
  id: number;
  result: DecodeBundleResult;
};

self.onmessage = (event: MessageEvent<DecodeRequest>) => {
  const { id, payloads, passphrase, vaultBlob } = event.data;
  const result = decodeBundle(payloads, { passphrase, vaultBlob });
  self.postMessage({ id, result } satisfies DecodeResponse);
};
