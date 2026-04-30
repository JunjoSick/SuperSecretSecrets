import type { DecryptionProofEnvelope } from './decryption-proof-envelope';
import type { DecryptionProofPublicInputsV1 } from './decryption-proof-transcript';

export type DecryptionProofWitnessV1 = {
  kemSeed: Uint8Array;
  vaultRootKey: Uint8Array;
};

export type DecryptionProofProgressEvent =
  | { phase: 'initializing'; progress?: number }
  | { phase: 'witness'; progress?: number }
  | { phase: 'proving'; progress?: number }
  | { phase: 'local-verifying'; progress?: number }
  | { phase: 'zeroizing'; progress?: number }
  | { phase: 'done'; progress: 1 };

export type DecryptionProofProverInputV1 = {
  publicInputs: DecryptionProofPublicInputsV1;
  witness: DecryptionProofWitnessV1;
  signal?: AbortSignal;
  onProgress?: (event: DecryptionProofProgressEvent) => void;
};

export type DecryptionProofProver = {
  schemeId: number;
  relationId: string;
  relationDigest: Uint8Array;
  verifierArtifactDigest: Uint8Array;
  proveV1(input: DecryptionProofProverInputV1): Promise<DecryptionProofEnvelope>;
};
