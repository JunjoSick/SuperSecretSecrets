import { decodeSecret, type DecodeResult } from '../crypto';

type DecodeRequest = {
  id: number;
  payloads: string[];
  passphrase?: string;
};

type DecodeResponse = {
  id: number;
  result: DecodeResult;
};

self.onmessage = (event: MessageEvent<DecodeRequest>) => {
  const { id, payloads, passphrase } = event.data;
  const result = decodeSecret(payloads, passphrase);
  self.postMessage({ id, result } satisfies DecodeResponse);
};
