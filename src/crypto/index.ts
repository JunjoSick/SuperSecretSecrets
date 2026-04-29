import {
  keygenFromSeed,
  encapsulate,
  decapsulate,
  KEM_SEED_LEN,
  type KemAlg,
} from './pq';
import {
  aeadEncrypt,
  aeadDecrypt,
  AEAD_KEY_LEN,
  AEAD_NONCE_LEN,
  type AeadAlg,
} from './aead';
import {
  deriveKey,
  stretchPassphrase,
  ARGON2_DEFAULTS,
  type KdfAlg,
  type Argon2Params,
} from './kdf';
import { split, combine } from './shamir';
import {
  encodeHeaderChunk,
  encodeHeaderChunkV2,
  encodeHeaderChunkV3,
  encodeShare,
  encodeShareV2,
  encodeShareV3,
  parse,
  toBase45,
  fromBase45,
  KIND_HEADER,
  KIND_SHARE,
  TLV_BUNDLE_METADATA,
  TLV_PLAINTEXT_COMMITMENT,
  TLV_POLICY_COMMITMENT,
  TLV_POLICY_MANIFEST,
  TLV_PAYLOAD_FORMAT,
  TLV_SHARE_METADATA,
  TLV_SHARE_METADATA_MAC,
  TLV_SHARE_COMMIT_PROOF,
  TLV_TIMELOCK,
  TLV_VAULT_INFO,
  TLV_VAULT_TREE_ROOT,
  TLV_VDF_LOCK,
  TLV_VDF_PARAMS,
  TLV_VDF_PROOF,
  TLV_DECRYPTION_PROOF,
  makeTlv,
  VERSION,
  VERSION_V2,
  VERSION_V3,
  type HeaderChunkQr,
  type ParsedQr,
  type ShareQr,
  type Tlv,
} from './codec';
import { commitPolicyManifest, verifyPolicyManifestCommitment } from './zk/manifest';
import {
  bindPlaintextCommitment,
  verifyPlaintextCommitment,
  type DecryptionProofVerification,
  type DecryptionProofVerifier,
} from './zk/decryption-proof';
import {
  DECRYPTION_PROOF_HARD_MAX_BYTES,
  DECRYPTION_PROOF_WARN_MAX_BYTES,
  decodeDecryptionProofEnvelope as decodeCanonicalDecryptionProofEnvelope,
  encodeDecryptionProofEnvelope as encodeCanonicalDecryptionProofEnvelope,
} from './zk/decryption-proof-envelope';
import type {
  DecryptionProofProgressEvent,
  DecryptionProofProver,
} from './zk/decryption-proof-prover';
import {
  RELATION_V1_VAULTROOT_ONLY_DIGEST,
  proofFacingCommitmentsUsePoseidon2Bn254,
  getSupportedDecryptionProofRelation,
} from './zk/decryption-proof-relations';
import {
  buildDecryptionProofPublicInputsFromDecodedHeaderV1,
  digestDecryptionProofPublicInputsV1,
  type DecryptionProofPublicInputsV1,
} from './zk/decryption-proof-transcript';
import {
  verifyDecryptionProofEnvelopeV1,
  type DecryptionProofVerifier as CanonicalDecryptionProofVerifier,
} from './zk/decryption-proof-verifier';
import {
  bindPoseidon2Bn254PolicySeedCommitment,
  bindPoseidon2Bn254VaultRootPlaintextCommitment,
  commitPoseidon2Bn254VaultTreeRoot,
} from './commitments/proof-facing';
import { getDefaultPoseidon2Bn254Implementation } from './commitments/poseidon2-zkpassport';
import { hashToScalar, POINT_LEN } from './zk/curve';
import { commitmentFromBytes, commitmentToBytes, pedersenCommit } from './zk/pedersen';
import {
  decodeSchnorrProof,
  encodeSchnorrProof,
  schnorrProveCommit,
  schnorrVerifyCommit,
  SCHNORR_PROOF_LEN,
} from './zk/schnorr';
import { proveVaultEntry, vaultTreeRoot, verifyVaultEntry } from './zk/vault-tree';
import type { MerkleProof } from './zk/merkle';
import { hashToForm, sampleDiscriminant } from './vdf/wesolowski';
import { equal as formsEqual } from './vdf/classgroup';
import {
  decodeVdfParams,
  decodeVdfProof,
  decodeVdfShareLock,
  encodeVdfParams,
  encodeVdfProof,
  encodeVdfShareLock,
  type VdfParams,
  vdfLockShare,
  vdfUnlockShare,
} from './vdf/timelock';
import {
  decodeShareMetadata,
  deriveMetadataKey,
  encodeShareMetadata,
  metadataMac,
  verifyMetadataMac,
  type MetadataVerification,
  type ShareMetadata,
} from './metadata';
import {
  compileFlatPolicy,
  compileTreePolicy,
  decodePolicyManifest,
  decodeShareComponents,
  encodePolicyManifest,
  encodeShareComponents,
  recoverPolicySecret,
  type Custodian,
  type PolicyManifest,
  type PolicyNode,
  type PolicyProgress,
  type ShareComponent,
} from './policy';
import {
  createVaultBlob,
  decodeVaultInfo,
  decryptVault,
  encodeVaultInfo,
  generateVaultRootKey,
  inspectVaultBlob,
  VAULT_FORMAT_VERSION,
  type VaultEntry,
  type VaultPlaintext,
} from './vault';
import {
  decodeTimeLockInfo,
  encodeTimeLockInfo,
  lockSharePayload,
  unlockSharePayload,
  type TimeLockAdapter,
  type TimeLockInfo,
  type TimeLockOptions,
} from './timelock';

export type EncodeOptions = {
  threshold: number; // T
  shares: number; // N
  kemAlg: KemAlg;
  aeadAlg: AeadAlg;
  kdfAlg: KdfAlg;
  passphrase?: string;
  argon2?: Argon2Params;
  /** Max bytes per header QR payload (after header-frame overhead). Default 800. */
  maxHeaderBytes?: number;
  custodians?: Custodian[];
  policy?: PolicyNode;
  metadata?: ShareMetadata;
  vaultMode?: boolean;
  vaultEntries?: VaultEntry[];
  timeLocks?: TimeLockOptions;
  /** Emit v3 ZK commitments: policy-manifest + plaintext + (when vault) vault-tree. */
  zk?: boolean;
  /** Lock each share behind a Wesolowski class-group VDF that takes T sequential squarings to unlock. */
  vdf?: { T: bigint; discriminantBits?: number };
  /** Opt-in async auditor decryption proof emission for supported v3 vault-root bundles. */
  decryptionProof?: {
    enabled: boolean;
    prover?: DecryptionProofProver;
    verifiers?: readonly CanonicalDecryptionProofVerifier[];
    allowLargeProof?: boolean;
  };
};

export type VdfProgressInfo = {
  phase: 'lock' | 'unlock';
  shareIdx: number;
  shareOrdinal: number;
  shareTotal: number;
  done: bigint;
  total: bigint;
};

export type ZkProgressInfo = {
  check: 'policy' | 'plaintext' | 'vault-tree';
  status: 'verifying' | 'verified' | 'tampered';
  done: number;
  total: number;
};

export type EncodeRuntimeOptions = {
  onVdfProgress?: (info: VdfProgressInfo) => void;
  onDecryptionProofProgress?: (event: DecryptionProofProgressEvent) => void;
  signal?: AbortSignal;
};

export const DEFAULT_OPTIONS: EncodeOptions = {
  threshold: 3,
  shares: 5,
  kemAlg: 'ml-kem-768',
  aeadAlg: 'aes-256-gcm',
  kdfAlg: 'hkdf-sha256',
  maxHeaderBytes: 800,
};

export type EncodedBundle = {
  bundleId: Uint8Array;
  options: EncodeOptions;
  formatVersion?: 1 | 2 | 3;
  /** Base45-encoded QR payloads for the header, split across `chunkTotal` codes. */
  headerQrs: string[];
  /** Base45-encoded QR payloads, one per Shamir share. */
  shareQrs: string[];
  vaultBlob?: Uint8Array;
  vaultId?: Uint8Array;
};

const INFO_AEAD = 'SSS/AEAD/v1';
const INFO_PASSPHRASE = 'SSS/passphrase/v1';
const BUNDLE_ID_LEN = 8;
const vdfDiscriminantCache = new Map<number, bigint>();

function randBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function concat(...chunks: Uint8Array[]): Uint8Array {
  const len = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(len);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

function buildAeadKey(
  sharedSecret: Uint8Array,
  opts: EncodeOptions,
  salt: Uint8Array,
): Uint8Array {
  let key = deriveKey(opts.kdfAlg, sharedSecret, salt, INFO_AEAD, AEAD_KEY_LEN);
  if (opts.passphrase && opts.passphrase.length > 0) {
    const stretched = stretchPassphrase(opts.passphrase, salt, opts.argon2);
    const mixed = new Uint8Array(AEAD_KEY_LEN);
    for (let i = 0; i < AEAD_KEY_LEN; i++) mixed[i] = key[i]! ^ stretched[i]!;
    key = deriveKey(opts.kdfAlg, mixed, salt, INFO_PASSPHRASE, AEAD_KEY_LEN);
  }
  return key;
}

export function encodeSecret(
  plaintext: string,
  optsIn: Partial<EncodeOptions> = {},
  runtime: EncodeRuntimeOptions = {},
): EncodedBundle {
  const opts: EncodeOptions = { ...DEFAULT_OPTIONS, ...optsIn };
  if (shouldUseV2(opts)) return encodeSecretV2(plaintext, opts, runtime);
  return encodeSecretV1(plaintext, opts);
}

export async function encodeSecretAsync(
  plaintext: string,
  optsIn: Partial<EncodeOptions> = {},
  runtime: EncodeRuntimeOptions = {},
): Promise<EncodedBundle> {
  const opts: EncodeOptions = { ...DEFAULT_OPTIONS, ...optsIn };
  if (shouldUseV2(opts)) return encodeSecretV2Async(plaintext, opts, runtime);
  if (opts.decryptionProof?.enabled) {
    const support = getSupportedDecryptionProofRelation({
      formatVersion: 3,
      payloadKind: 'secret',
      kemAlg: opts.kemAlg,
      kdfAlg: opts.kdfAlg,
      aeadAlg: opts.aeadAlg,
      passphrase: !!(opts.passphrase && opts.passphrase.length > 0),
    });
    if (support.supported) throw new Error('internal decryption proof support error for secret payload');
  }
  return encodeSecretV1(plaintext, opts);
}

export function clearVdfDiscriminantCache(): void {
  vdfDiscriminantCache.clear();
}

function encodeSecretV1(plaintext: string, opts: EncodeOptions): EncodedBundle {
  if (opts.shares < opts.threshold) throw new Error('shares must be >= threshold');

  const pt = new TextEncoder().encode(plaintext);
  const bundleId = randBytes(BUNDLE_ID_LEN);
  const kemSeed = randBytes(KEM_SEED_LEN);

  const { secretKey, publicKey } = keygenFromSeed(opts.kemAlg, kemSeed);
  const { cipherText: kemCt, sharedSecret } = encapsulate(opts.kemAlg, publicKey);
  // Drop the secret key from memory — the seed (Shamir-split) is the long-term secret.
  secretKey.fill(0);

  const aeadNonce = randBytes(AEAD_NONCE_LEN);
  const salt = bundleId; // public, fixed-length per bundle; fine as a KDF salt
  const aeadKey = buildAeadKey(sharedSecret, opts, salt);
  const aeadCt = aeadEncrypt(opts.aeadAlg, aeadKey, aeadNonce, pt);
  aeadKey.fill(0);
  sharedSecret.fill(0);

  // Header payload = kem_ct || nonce || aead_ct_and_tag
  const headerPayload = concat(kemCt, aeadNonce, aeadCt);

  const argon2 = opts.argon2 ?? ARGON2_DEFAULTS;
  // Encode memory as log2(KiB), rounded down but ensuring round-trip fidelity for defaults.
  const memLog2KiB = Math.round(Math.log2(argon2.m));
  const headerArgon2 = { tCost: argon2.t, memLog2KiB, parallelism: argon2.p };
  const flags = { passphrase: !!(opts.passphrase && opts.passphrase.length > 0) };

  const headerChunks = chunkBytes(headerPayload, opts.maxHeaderBytes ?? 800);
  const headerQrs = headerChunks.map((chunk, idx) => {
    const framed = encodeHeaderChunk({
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: opts.threshold,
      n: opts.shares,
      chunkIdx: idx,
      chunkTotal: headerChunks.length,
      payload: chunk,
    });
    return toBase45(framed);
  });

  const shamirShares = split(kemSeed, opts.threshold, opts.shares);
  const shareQrs = shamirShares.map((s) =>
    toBase45(
      encodeShare({
        bundleId,
        kemAlg: opts.kemAlg,
        t: opts.threshold,
        n: opts.shares,
        shareIdx: s[0]!,
        share: s,
      }),
    ),
  );

  kemSeed.fill(0);

  return { bundleId, options: opts, formatVersion: 1, headerQrs, shareQrs };
}

function encodeSecretV2(plaintext: string, opts: EncodeOptions, runtime: EncodeRuntimeOptions): EncodedBundle {
  const custodians = effectiveCustodians(opts);
  const totalPoints = custodians.reduce((sum, c) => sum + (c.weight ?? 1), 0);
  if (totalPoints > 255) throw new Error('weighted point count must be <= 255');

  const pt = new TextEncoder().encode(plaintext);
  const bundleId = randBytes(BUNDLE_ID_LEN);
  const kemSeed = randBytes(KEM_SEED_LEN);

  const { secretKey, publicKey } = keygenFromSeed(opts.kemAlg, kemSeed);
  const { cipherText: kemCt, sharedSecret } = encapsulate(opts.kemAlg, publicKey);
  secretKey.fill(0);

  let vaultBlob: Uint8Array | undefined;
  let vaultId: Uint8Array | undefined;
  let protectedPayload: Uint8Array = pt;
  if (opts.vaultMode) {
    const rootKey = new Uint8Array(generateVaultRootKey());
    const entries = opts.vaultEntries ?? [
      { id: 'secret', name: 'secret.txt', data: pt, contentType: 'text/plain; charset=utf-8' },
    ];
    const vault = createVaultBlob(rootKey, entries);
    vaultBlob = vault.blob;
    vaultId = vault.vaultId;
    protectedPayload = rootKey;
  }

  const aeadNonce = randBytes(AEAD_NONCE_LEN);
  const salt = bundleId;
  const aeadKey = buildAeadKey(sharedSecret, opts, salt);
  const aeadCt = aeadEncrypt(opts.aeadAlg, aeadKey, aeadNonce, protectedPayload);
  const ptCommit = opts.zk ? bindPlaintextCommitment(bundleId, protectedPayload) : null;
  aeadKey.fill(0);
  sharedSecret.fill(0);
  if (opts.vaultMode) protectedPayload.fill(0);

  const headerPayload = concat(kemCt, aeadNonce, aeadCt);
  const argon2 = opts.argon2 ?? ARGON2_DEFAULTS;
  const memLog2KiB = Math.round(Math.log2(argon2.m));
  const headerArgon2 = { tCost: argon2.t, memLog2KiB, parallelism: argon2.p };
  const flags = { passphrase: !!(opts.passphrase && opts.passphrase.length > 0) };

  const compiled = opts.policy
    ? compileTreePolicy(kemSeed, opts.policy, custodians)
    : compileFlatPolicy(kemSeed, opts.threshold, custodians);
  const policyManifest = compiled.manifest;
  const policyCommitRoot = opts.zk ? commitPolicyManifest(policyManifest) : null;
  const vaultTreeRootBytes =
    opts.zk && opts.vaultMode
      ? vaultTreeRoot(
          opts.vaultEntries ?? [
            { id: 'secret', name: 'secret.txt', data: pt, contentType: 'text/plain; charset=utf-8' },
          ],
        )
      : null;
  const metadataKey = deriveMetadataKey(kemSeed, bundleId);
  const headerChunks = chunkBytes(headerPayload, opts.maxHeaderBytes ?? 800);
  const payloadKind = opts.vaultMode ? 'vault-root' : 'secret';
  let vdfParams: VdfParams | null = null;
  if (opts.vdf) {
    if (opts.vdf.T < 0n) throw new Error('vdf.T must be non-negative');
    const delta = cachedVdfDiscriminant(opts.vdf.discriminantBits ?? 128);
    vdfParams = { delta, T: opts.vdf.T };
  }
  const useV3 = !!opts.zk || !!opts.vdf;
  const encodeHeader = useV3 ? encodeHeaderChunkV3 : encodeHeaderChunkV2;
  const encodeShareFn = useV3 ? encodeShareV3 : encodeShareV2;

  const headerQrs = headerChunks.map((chunk, idx) => {
    const extensions =
      idx === 0
        ? [
            makeTlv(TLV_POLICY_MANIFEST, encodePolicyManifest(policyManifest), true),
            makeTlv(TLV_PAYLOAD_FORMAT, textBytes(payloadKind), true),
            ...(opts.metadata ? [makeTlv(TLV_BUNDLE_METADATA, encodeShareMetadata(opts.metadata), false)] : []),
            ...(vaultId ? [makeTlv(TLV_VAULT_INFO, encodeVaultInfo({ vaultId, formatVersion: VAULT_FORMAT_VERSION }), true)] : []),
            ...(policyCommitRoot ? [makeTlv(TLV_POLICY_COMMITMENT, policyCommitRoot, true)] : []),
            ...(ptCommit ? [makeTlv(TLV_PLAINTEXT_COMMITMENT, ptCommit, true)] : []),
            ...(vaultTreeRootBytes ? [makeTlv(TLV_VAULT_TREE_ROOT, vaultTreeRootBytes, true)] : []),
            ...(vdfParams ? [makeTlv(TLV_VDF_PARAMS, encodeVdfParams(vdfParams), true)] : []),
          ]
        : [];
    const framed = encodeHeader({
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: policyManifest.threshold,
      n: policyManifest.totalPoints,
      chunkIdx: idx,
      chunkTotal: headerChunks.length,
      extensions,
      payload: chunk,
    });
    return toBase45(framed);
  });

  const shareQrs = compiled.shares.map((share, shareOffset) => {
    const metadata = shareMetadataFor(opts.metadata, share.custodian);
    const componentIds = share.components.map((component) => component.id);
    const metadataBytes = encodeShareMetadata(metadata);
    const mac = metadataMac(metadataKey, metadata, {
      bundleId,
      shareIdx: share.shareIdx,
      componentIds,
    });
    const componentPayload = encodeShareComponents(share.components);
    let payload = componentPayload;
    const extensions = [
      makeTlv(TLV_PAYLOAD_FORMAT, textBytes('policy-components'), true),
      makeTlv(TLV_SHARE_METADATA, metadataBytes, false),
      makeTlv(TLV_SHARE_METADATA_MAC, mac, false),
    ];
    if (opts.zk) {
      extensions.push(
        makeTlv(
          TLV_SHARE_COMMIT_PROOF,
          encodeShareCommitProof(componentPayload, metadataKey, bundleId, share.shareIdx),
          true,
        ),
      );
    }
    if (opts.timeLocks) {
      const locked = lockSharePayload(payload, opts.timeLocks);
      payload = locked.ciphertext;
      extensions.push(makeTlv(TLV_TIMELOCK, encodeTimeLockInfo(locked.info), true));
    }
    if (vdfParams) {
      const shareSeed = concat(bundleId, new Uint8Array([share.shareIdx]));
      const { ciphertext, lock, proof } = vdfLockShare(payload, vdfParams, shareSeed, randBytes, (done, total) => {
        runtime.onVdfProgress?.({
          phase: 'lock',
          shareIdx: share.shareIdx,
          shareOrdinal: shareOffset + 1,
          shareTotal: compiled.shares.length,
          done,
          total,
        });
      });
      payload = ciphertext;
      extensions.push(makeTlv(TLV_VDF_LOCK, encodeVdfShareLock(lock), true));
      extensions.push(makeTlv(TLV_VDF_PROOF, encodeVdfProof(proof), true));
    }
    return toBase45(
      encodeShareFn({
        bundleId,
        kemAlg: opts.kemAlg,
        t: policyManifest.threshold,
        n: policyManifest.totalPoints,
        shareIdx: share.shareIdx,
        extensions,
        share: payload,
      }),
    );
  });

  metadataKey.fill(0);
  kemSeed.fill(0);

  return {
    bundleId,
    options: { ...opts, shares: compiled.shares.length, threshold: policyManifest.threshold },
    formatVersion: useV3 ? 3 : 2,
    headerQrs,
    shareQrs,
    vaultBlob,
    vaultId,
  };
}

async function encodeSecretV2Async(
  plaintext: string,
  opts: EncodeOptions,
  runtime: EncodeRuntimeOptions,
): Promise<EncodedBundle> {
  if (runtime.signal?.aborted) throw new Error('encode cancelled');
  const custodians = effectiveCustodians(opts);
  const totalPoints = custodians.reduce((sum, c) => sum + (c.weight ?? 1), 0);
  if (totalPoints > 255) throw new Error('weighted point count must be <= 255');

  const proofRequested = opts.decryptionProof?.enabled === true;
  const emitZk = opts.zk === true || proofRequested;
  const pt = new TextEncoder().encode(plaintext);
  const bundleId = randBytes(BUNDLE_ID_LEN);
  const kemSeed = randBytes(KEM_SEED_LEN);

  const { secretKey, publicKey } = keygenFromSeed(opts.kemAlg, kemSeed);
  const { cipherText: kemCt, sharedSecret } = encapsulate(opts.kemAlg, publicKey);
  secretKey.fill(0);

  let vaultBlob: Uint8Array | undefined;
  let vaultId: Uint8Array | undefined;
  let protectedPayload: Uint8Array = pt;
  const entries = opts.vaultEntries ?? [
    { id: 'secret', name: 'secret.txt', data: pt, contentType: 'text/plain; charset=utf-8' },
  ];
  if (opts.vaultMode) {
    const rootKey = new Uint8Array(generateVaultRootKey());
    const vault = createVaultBlob(rootKey, entries);
    vaultBlob = vault.blob;
    vaultId = vault.vaultId;
    protectedPayload = rootKey;
  }
  const vaultRootKeyForProof = opts.vaultMode ? protectedPayload.slice() : null;

  const aeadNonce = randBytes(AEAD_NONCE_LEN);
  const salt = bundleId;
  const aeadKey = buildAeadKey(sharedSecret, opts, salt);
  const aeadCt = aeadEncrypt(opts.aeadAlg, aeadKey, aeadNonce, protectedPayload);
  aeadKey.fill(0);
  sharedSecret.fill(0);

  const headerPayload = concat(kemCt, aeadNonce, aeadCt);
  const flags = { passphrase: !!(opts.passphrase && opts.passphrase.length > 0) };
  const payloadKind = opts.vaultMode ? 'vault-root' : 'secret';
  const proofSupport = proofRequested
    ? getSupportedDecryptionProofRelation({
        formatVersion: 3,
        payloadKind,
        kemAlg: opts.kemAlg,
        kdfAlg: opts.kdfAlg,
        aeadAlg: opts.aeadAlg,
        passphrase: flags.passphrase,
      })
    : null;
  const proofEligible = proofSupport?.supported === true;
  const argon2 = opts.argon2 ?? ARGON2_DEFAULTS;
  const memLog2KiB = Math.round(Math.log2(argon2.m));
  const headerArgon2 = proofEligible
    ? { tCost: 0, memLog2KiB: 0, parallelism: 0 }
    : { tCost: argon2.t, memLog2KiB, parallelism: argon2.p };
  const proofCommitmentBackend = proofEligible ? getDefaultPoseidon2Bn254Implementation() : undefined;
  const ptCommit = emitZk
    ? proofEligible && opts.vaultMode
      ? bindPoseidon2Bn254VaultRootPlaintextCommitment({
          bundleId,
          vaultRootKey: protectedPayload,
          implementation: proofCommitmentBackend,
        })
      : bindPlaintextCommitment(bundleId, protectedPayload)
    : null;

  const compiled = opts.policy
    ? compileTreePolicy(kemSeed, opts.policy, custodians)
    : compileFlatPolicy(kemSeed, opts.threshold, custodians);
  const policyManifest = compiled.manifest;
  const policyCommitRoot = emitZk
    ? proofEligible
      ? bindPoseidon2Bn254PolicySeedCommitment({
          kemSeed,
          implementation: proofCommitmentBackend,
        })
      : commitPolicyManifest(policyManifest)
    : null;
  const vaultTreeRootBytes = emitZk && opts.vaultMode
    ? proofEligible
      ? commitPoseidon2Bn254VaultTreeRoot({
          entries,
          implementation: proofCommitmentBackend,
        })
      : vaultTreeRoot(entries)
    : null;
  const metadataKey = deriveMetadataKey(kemSeed, bundleId);
  const headerChunks = chunkBytes(headerPayload, opts.maxHeaderBytes ?? 800);

  let vdfParams: VdfParams | null = null;
  if (opts.vdf) {
    if (opts.vdf.T < 0n) throw new Error('vdf.T must be non-negative');
    const delta = cachedVdfDiscriminant(opts.vdf.discriminantBits ?? 128);
    vdfParams = { delta, T: opts.vdf.T };
  }
  const useV3 = emitZk || !!opts.vdf;
  const encodeHeader = useV3 ? encodeHeaderChunkV3 : encodeHeaderChunkV2;
  const encodeShareFn = useV3 ? encodeShareV3 : encodeShareV2;

  let decryptionProofTlv: Tlv | null = null;
  if (proofEligible) {
    const proofOptions = opts.decryptionProof;
    if (!proofOptions?.prover) throw new Error('decryption proof prover is required for supported bundles');
    const { prover } = proofOptions;
    if (
      prover.relationId !== proofSupport.relationId ||
      !bytesEqual(prover.relationDigest, RELATION_V1_VAULTROOT_ONLY_DIGEST)
    ) {
      throw new Error('decryption proof prover relation does not match the current supported relation');
    }
    if (!policyCommitRoot || !ptCommit || !vaultTreeRootBytes || !vaultRootKeyForProof) {
      throw new Error('decryption proof requires v3 vault-root commitments');
    }
    const firstHeaderLike: HeaderChunkQr = {
      kind: KIND_HEADER,
      version: VERSION_V3,
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: policyManifest.threshold,
      n: policyManifest.totalPoints,
      chunkIdx: 0,
      chunkTotal: headerChunks.length,
      payload: headerChunks[0] ?? new Uint8Array(0),
    };
    const publicInputs = buildDecryptionProofPublicInputsFromDecodedHeaderV1({
      firstHeader: firstHeaderLike,
      fullHeaderPayload: headerPayload,
      payloadKind,
      policyCommitment: policyCommitRoot,
      plaintextCommitment: ptCommit,
      vaultTreeRoot: vaultTreeRootBytes,
    });
    const witness = {
      kemSeed: kemSeed.slice(),
      vaultRootKey: vaultRootKeyForProof.slice(),
    };
    try {
      if (runtime.signal?.aborted) throw new Error('encode cancelled');
      const envelope = await prover.proveV1({
        publicInputs,
        witness,
        signal: runtime.signal,
        onProgress: runtime.onDecryptionProofProgress,
      });
      if (runtime.signal?.aborted) throw new Error('encode cancelled');
      runtime.onDecryptionProofProgress?.({ phase: 'local-verifying' });
      const verification = await verifyDecryptionProofEnvelopeV1({
        envelope,
        publicInputs,
        verifiers: proofOptions.verifiers,
        signal: runtime.signal,
      });
      if (runtime.signal?.aborted) throw new Error('encode cancelled');
      if (verification.status !== 'verified') {
        throw new Error(`local decryption proof verification failed: ${verification.reason}`);
      }
      const proofBytes = encodeCanonicalDecryptionProofEnvelope(envelope);
      if (proofBytes.length > DECRYPTION_PROOF_HARD_MAX_BYTES) {
        throw new Error('decryption proof is too large for QR-carried TLV');
      }
      if (proofBytes.length > DECRYPTION_PROOF_WARN_MAX_BYTES && !proofOptions.allowLargeProof) {
        throw new Error('decryption proof exceeds warning size limit; enable allowLargeProof to emit it');
      }
      decryptionProofTlv = makeTlv(TLV_DECRYPTION_PROOF, proofBytes, false);
    } finally {
      witness.kemSeed.fill(0);
      witness.vaultRootKey.fill(0);
      runtime.onDecryptionProofProgress?.({ phase: 'zeroizing' });
    }
  }

  if (opts.vaultMode) protectedPayload.fill(0);
  vaultRootKeyForProof?.fill(0);

  const headerQrs = headerChunks.map((chunk, idx) => {
    const extensions =
      idx === 0
        ? [
            makeTlv(TLV_POLICY_MANIFEST, encodePolicyManifest(policyManifest), true),
            makeTlv(TLV_PAYLOAD_FORMAT, textBytes(payloadKind), true),
            ...(opts.metadata ? [makeTlv(TLV_BUNDLE_METADATA, encodeShareMetadata(opts.metadata), false)] : []),
            ...(vaultId ? [makeTlv(TLV_VAULT_INFO, encodeVaultInfo({ vaultId, formatVersion: VAULT_FORMAT_VERSION }), true)] : []),
            ...(policyCommitRoot ? [makeTlv(TLV_POLICY_COMMITMENT, policyCommitRoot, true)] : []),
            ...(ptCommit ? [makeTlv(TLV_PLAINTEXT_COMMITMENT, ptCommit, true)] : []),
            ...(vaultTreeRootBytes ? [makeTlv(TLV_VAULT_TREE_ROOT, vaultTreeRootBytes, true)] : []),
            ...(vdfParams ? [makeTlv(TLV_VDF_PARAMS, encodeVdfParams(vdfParams), true)] : []),
            ...(decryptionProofTlv ? [decryptionProofTlv] : []),
          ]
        : [];
    const framed = encodeHeader({
      bundleId,
      kemAlg: opts.kemAlg,
      aeadAlg: opts.aeadAlg,
      kdfAlg: opts.kdfAlg,
      flags,
      argon2: headerArgon2,
      t: policyManifest.threshold,
      n: policyManifest.totalPoints,
      chunkIdx: idx,
      chunkTotal: headerChunks.length,
      extensions,
      payload: chunk,
    });
    return toBase45(framed);
  });

  const shareQrs = compiled.shares.map((share, shareOffset) => {
    const metadata = shareMetadataFor(opts.metadata, share.custodian);
    const componentIds = share.components.map((component) => component.id);
    const metadataBytes = encodeShareMetadata(metadata);
    const mac = metadataMac(metadataKey, metadata, {
      bundleId,
      shareIdx: share.shareIdx,
      componentIds,
    });
    const componentPayload = encodeShareComponents(share.components);
    let payload = componentPayload;
    const extensions = [
      makeTlv(TLV_PAYLOAD_FORMAT, textBytes('policy-components'), true),
      makeTlv(TLV_SHARE_METADATA, metadataBytes, false),
      makeTlv(TLV_SHARE_METADATA_MAC, mac, false),
    ];
    if (emitZk) {
      extensions.push(
        makeTlv(
          TLV_SHARE_COMMIT_PROOF,
          encodeShareCommitProof(componentPayload, metadataKey, bundleId, share.shareIdx),
          true,
        ),
      );
    }
    if (opts.timeLocks) {
      const locked = lockSharePayload(payload, opts.timeLocks);
      payload = locked.ciphertext;
      extensions.push(makeTlv(TLV_TIMELOCK, encodeTimeLockInfo(locked.info), true));
    }
    if (vdfParams) {
      const shareSeed = concat(bundleId, new Uint8Array([share.shareIdx]));
      const { ciphertext, lock, proof } = vdfLockShare(payload, vdfParams, shareSeed, randBytes, (done, total) => {
        runtime.onVdfProgress?.({
          phase: 'lock',
          shareIdx: share.shareIdx,
          shareOrdinal: shareOffset + 1,
          shareTotal: compiled.shares.length,
          done,
          total,
        });
      });
      payload = ciphertext;
      extensions.push(makeTlv(TLV_VDF_LOCK, encodeVdfShareLock(lock), true));
      extensions.push(makeTlv(TLV_VDF_PROOF, encodeVdfProof(proof), true));
    }
    return toBase45(
      encodeShareFn({
        bundleId,
        kemAlg: opts.kemAlg,
        t: policyManifest.threshold,
        n: policyManifest.totalPoints,
        shareIdx: share.shareIdx,
        extensions,
        share: payload,
      }),
    );
  });

  metadataKey.fill(0);
  kemSeed.fill(0);

  return {
    bundleId,
    options: { ...opts, shares: compiled.shares.length, threshold: policyManifest.threshold },
    formatVersion: useV3 ? 3 : 2,
    headerQrs,
    shareQrs,
    vaultBlob,
    vaultId,
  };
}

function shouldUseV2(opts: EncodeOptions): boolean {
  return Boolean(
    opts.policy ||
      opts.custodians ||
      opts.metadata ||
      opts.vaultMode ||
      opts.vaultEntries ||
      opts.timeLocks ||
      opts.zk ||
      opts.vdf,
  );
}

function cachedVdfDiscriminant(discriminantBits: number): bigint {
  const bits = Math.trunc(discriminantBits);
  if (bits < 32) throw new Error('vdf.discriminantBits must be >= 32');
  const cached = vdfDiscriminantCache.get(bits);
  if (cached !== undefined) return cached;
  const delta = sampleDiscriminant(bits);
  vdfDiscriminantCache.set(bits, delta);
  return delta;
}

function effectiveCustodians(opts: EncodeOptions): Custodian[] {
  if (opts.custodians && opts.custodians.length > 0) return opts.custodians;
  return Array.from({ length: opts.shares }, (_, i) => ({
    id: `share-${i + 1}`,
    name: `Share ${i + 1}`,
    weight: 1,
  }));
}

function shareMetadataFor(bundleMetadata: ShareMetadata | undefined, custodian: Custodian): ShareMetadata {
  return {
    ...bundleMetadata,
    ...custodian.metadata,
    custodianName: custodian.metadata?.custodianName ?? custodian.name ?? bundleMetadata?.custodianName,
  };
}

function chunkBytes(data: Uint8Array, maxSize: number): Uint8Array[] {
  if (maxSize < 1) throw new Error('maxSize must be >= 1');
  if (data.length <= maxSize) return [data];
  const out: Uint8Array[] = [];
  for (let o = 0; o < data.length; o += maxSize) {
    out.push(data.slice(o, Math.min(o + maxSize, data.length)));
  }
  return out;
}

export type DecodeNeedMore = {
  status: 'need-more';
  bundleId: Uint8Array | null;
  headerChunksSeen: number;
  headerChunksTotal: number | null;
  sharesSeen: number;
  threshold: number | null;
};

export type DecodeSuccess = {
  status: 'ok';
  bundleId: Uint8Array;
  plaintext: string;
};

export type DecodeError = {
  status: 'error';
  error: string;
};

export type DecodeResult = DecodeSuccess | DecodeNeedMore | DecodeError;

export type DecodedShareMetadata = {
  shareIdx: number;
  verification: MetadataVerification;
  zkVerification: ZkShareVerification;
};

export type ZkShareVerification = 'verified' | 'tampered' | 'unverified';

export type LockedShare = {
  shareIdx: number;
  timeLock: TimeLockInfo;
};

export type DecodeBundleNeedMore = DecodeNeedMore & {
  warnings: string[];
  policyProgress?: PolicyProgress;
  lockedShares: LockedShare[];
  metadata: DecodedShareMetadata[];
};

export type DecodeBundleSuccess =
  | {
      status: 'ok';
      kind: 'secret';
      bundleId: Uint8Array;
      plaintext: string;
      warnings: string[];
      decryptionProof?: DecryptionProofVerification;
      policyProgress?: PolicyProgress;
      metadata: DecodedShareMetadata[];
    }
  | {
      status: 'ok';
      kind: 'vault';
      bundleId: Uint8Array;
      vaultRootKey: Uint8Array;
      vaultId: Uint8Array;
      vaultTreeRoot?: Uint8Array;
      vault?: VaultPlaintext;
      warnings: string[];
      decryptionProof?: DecryptionProofVerification;
      policyProgress?: PolicyProgress;
      metadata: DecodedShareMetadata[];
    };

export type DecodeBundleError = DecodeError & {
  warnings?: string[];
};

export type DecodeBundleResult = DecodeBundleSuccess | DecodeBundleNeedMore | DecodeBundleError;

export type DecodeBundleOptions = {
  passphrase?: string;
  vaultBlob?: Uint8Array;
  timeLockAdapter?: TimeLockAdapter;
  onVdfProgress?: (info: VdfProgressInfo) => void;
  onZkProgress?: (info: ZkProgressInfo) => void;
  decryptionProofVerifiers?: readonly DecryptionProofVerifier[];
  decryptionProofV1Verifiers?: readonly CanonicalDecryptionProofVerifier[];
  verifyDecryptionProof?: boolean;
};

export type DecodeBundleAsyncOptions = DecodeBundleOptions & {
  signal?: AbortSignal;
};

export type { DecryptionProofVerification, DecryptionProofVerifier } from './zk/decryption-proof';

export type VaultDisclosure = {
  bundleId: Uint8Array;
  vaultId: Uint8Array;
  root: Uint8Array;
  entry: VaultEntry;
  proof: MerkleProof;
};

export type VaultDisclosureJson = {
  magic: 'SSS3_VAULT_DISCLOSURE';
  version: 1;
  bundleId: string;
  vaultId: string;
  root: string;
  entry: {
    id: string;
    name: string;
    contentType?: string;
    dataHex: string;
  };
  proof: {
    index: number;
    leafCount: number;
    siblings: string[];
  };
};

export function createVaultDisclosure(
  vault: VaultPlaintext,
  entryId: string,
  context: { bundleId: Uint8Array; vaultId: Uint8Array; root?: Uint8Array },
): VaultDisclosure | DecodeError {
  if (!bytesEqual(vault.vaultId, context.vaultId)) {
    return { status: 'error', error: 'vault id does not match disclosure context' };
  }
  const computedRoot = vaultTreeRoot(vault.entries);
  if (context.root && !bytesEqual(computedRoot, context.root)) {
    return { status: 'error', error: 'vault entries do not match published vault-tree root' };
  }
  const index = vault.entries.findIndex((entry) => entry.id === entryId);
  if (index < 0) return { status: 'error', error: `vault entry ${entryId} not found` };
  const { proof } = proveVaultEntry(vault.entries, index);
  return {
    bundleId: context.bundleId.slice(),
    vaultId: context.vaultId.slice(),
    root: (context.root ?? computedRoot).slice(),
    entry: copyVaultEntry(vault.entries[index]!),
    proof: copyMerkleProof(proof),
  };
}

export function decodeAndDiscloseVaultEntry(
  qrPayloads: string[],
  vaultBlob: Uint8Array,
  entryId: string,
  opts: Omit<DecodeBundleOptions, 'vaultBlob'> = {},
): VaultDisclosure | DecodeError {
  const decoded = decodeBundle(qrPayloads, { ...opts, vaultBlob });
  if (decoded.status === 'error') return decoded;
  if (decoded.status === 'need-more') {
    return { status: 'error', error: 'not enough QR material to disclose vault entry' };
  }
  if (decoded.kind !== 'vault') {
    return { status: 'error', error: 'decoded bundle is not a vault' };
  }
  if (!decoded.vault) {
    return { status: 'error', error: 'vault blob was not decrypted' };
  }
  const publishedRoot = inspectVaultTreeRoot(qrPayloads);
  if (!publishedRoot) {
    return { status: 'error', error: 'vault disclosure requires a v3 vault-tree root' };
  }
  return createVaultDisclosure(decoded.vault, entryId, {
    bundleId: decoded.bundleId,
    vaultId: decoded.vaultId,
    root: publishedRoot,
  });
}

export function verifyVaultDisclosure(disclosure: VaultDisclosure): boolean {
  return verifyVaultEntry(disclosure.entry, disclosure.proof, disclosure.root);
}

export function encodeVaultDisclosure(disclosure: VaultDisclosure): string {
  const json: VaultDisclosureJson = {
    magic: 'SSS3_VAULT_DISCLOSURE',
    version: 1,
    bundleId: hex(disclosure.bundleId),
    vaultId: hex(disclosure.vaultId),
    root: hex(disclosure.root),
    entry: {
      id: disclosure.entry.id,
      name: disclosure.entry.name,
      ...(disclosure.entry.contentType ? { contentType: disclosure.entry.contentType } : {}),
      dataHex: hex(disclosure.entry.data),
    },
    proof: {
      index: disclosure.proof.index,
      leafCount: disclosure.proof.leafCount,
      siblings: disclosure.proof.siblings.map(hex),
    },
  };
  return `${JSON.stringify(json, null, 2)}\n`;
}

export function decodeVaultDisclosure(serialized: string | Uint8Array): VaultDisclosure {
  const text = typeof serialized === 'string' ? serialized : new TextDecoder().decode(serialized);
  const parsed = JSON.parse(text) as VaultDisclosureJson;
  if (parsed.magic !== 'SSS3_VAULT_DISCLOSURE') throw new Error('not a vault disclosure');
  if (parsed.version !== 1) throw new Error('unsupported vault disclosure version');
  if (!parsed.entry || !parsed.proof) throw new Error('vault disclosure is missing entry or proof');
  const entry: VaultEntry = {
    id: parsed.entry.id,
    name: parsed.entry.name,
    data: fromHex(parsed.entry.dataHex),
  };
  if (parsed.entry.contentType) entry.contentType = parsed.entry.contentType;
  return {
    bundleId: fromHex(parsed.bundleId),
    vaultId: fromHex(parsed.vaultId),
    root: fromHex(parsed.root),
    entry,
    proof: {
      index: parsed.proof.index,
      leafCount: parsed.proof.leafCount,
      siblings: parsed.proof.siblings.map(fromHex),
    },
  };
}

export function inspectVaultTreeRoot(qrPayloads: string[]): Uint8Array | null {
  const headers: HeaderChunkQr[] = [];
  for (const payload of qrPayloads) {
    const parsed = parse(fromBase45(payload));
    if (parsed.kind === KIND_HEADER) headers.push(parsed);
  }
  const firstHeader = headers.find((header) => header.chunkIdx === 0) ?? headers[0];
  const root = firstHeader ? tlvValue(firstHeader, TLV_VAULT_TREE_ROOT) : undefined;
  return root ? root.slice() : null;
}

export function inspectQr(payload: string) {
  return parse(fromBase45(payload));
}

export function decodeSecret(qrPayloads: string[], passphrase?: string): DecodeResult {
  const result = decodeBundle(qrPayloads, { passphrase });
  if (result.status === 'need-more') {
    return {
      status: 'need-more',
      bundleId: result.bundleId,
      headerChunksSeen: result.headerChunksSeen,
      headerChunksTotal: result.headerChunksTotal,
      sharesSeen: result.sharesSeen,
      threshold: result.threshold,
    };
  }
  if (result.status === 'error') return { status: 'error', error: result.error };
  if (result.kind !== 'secret') {
    return { status: 'error', error: 'this bundle unlocks a .ssssvault blob; use decodeBundle with the vault blob' };
  }
  return { status: 'ok', bundleId: result.bundleId, plaintext: result.plaintext };
}

export function decodeBundle(qrPayloads: string[], opts: DecodeBundleOptions = {}): DecodeBundleResult {
  try {
    const parsed = qrPayloads.map((p) => parse(fromBase45(p)));
    if (parsed.length === 0) {
      return {
        status: 'need-more',
        bundleId: null,
        headerChunksSeen: 0,
        headerChunksTotal: null,
        sharesSeen: 0,
        threshold: null,
        warnings: [],
        lockedShares: [],
        metadata: [],
      };
    }

    const versions = new Set(parsed.map((p) => p.version));
    if (versions.size > 1) return { status: 'error', error: 'mixed SSS1/SSS2 QR payloads are not supported' };
    if (parsed[0]!.version === VERSION) return decodeV1Parsed(parsed, opts.passphrase);
    return decodeV2Parsed(parsed, opts);
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

export async function decodeBundleAsync(
  qrPayloads: string[],
  opts: DecodeBundleAsyncOptions = {},
): Promise<DecodeBundleResult> {
  try {
    const parsed = qrPayloads.map((p) => parse(fromBase45(p)));
    const proofInspection =
      opts.verifyDecryptionProof === false ? null : await inspectCanonicalDecryptionProofAsync(parsed, opts);
    if (proofInspection?.status === 'error') {
      return { status: 'error', error: proofInspection.error };
    }
    const decoded = decodeBundle(qrPayloads, { ...opts, verifyDecryptionProof: false });
    if (decoded.status !== 'ok' || !proofInspection?.decryptionProof) return decoded;
    const warnings =
      proofInspection.decryptionProof.status === 'unsupported'
        ? [
            ...decoded.warnings,
            `decryption proof scheme ${proofInspection.decryptionProof.schemeId} is unsupported`,
          ]
        : decoded.warnings;
    return { ...decoded, warnings, decryptionProof: proofInspection.decryptionProof };
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function decodeV1Parsed(parsed: ParsedQr[], passphrase?: string): DecodeBundleResult {
  try {
    if (parsed.some((p) => p.version !== VERSION)) {
      return { status: 'error', error: 'decodeV1Parsed received non-v1 QR payloads' };
    }

    // Group by bundleId; use the most-frequent one
    const groups = new Map<string, typeof parsed>();
    for (const p of parsed) {
      const k = hex(p.bundleId);
      const list = groups.get(k) ?? [];
      list.push(p);
      groups.set(k, list);
    }
    let best: typeof parsed = [];
    for (const [, list] of groups) {
      if (list.length > best.length) best = list;
    }
    const bundleId = best[0]!.bundleId;

    const headers = best.filter((p): p is HeaderChunkQr => p.kind === KIND_HEADER);
    const shares = best.filter((p): p is ShareQr => p.kind === KIND_SHARE);

    // Dedupe headers by chunkIdx, shares by shareIdx
    const headersByIdx = new Map<number, HeaderChunkQr>();
    for (const h of headers) headersByIdx.set(h.chunkIdx, h);
    const sharesByIdx = new Map<number, ShareQr>();
    for (const s of shares) sharesByIdx.set(s.shareIdx, s);

    const chunkTotal = headers[0]?.chunkTotal ?? null;
    const threshold = best.find((p) => p.kind === KIND_HEADER || p.kind === KIND_SHARE)?.t ?? null;

    const needMore = (): DecodeBundleNeedMore => ({
      status: 'need-more',
      bundleId,
      headerChunksSeen: headersByIdx.size,
      headerChunksTotal: chunkTotal,
      sharesSeen: sharesByIdx.size,
      threshold,
      warnings: [],
      lockedShares: [],
      metadata: [],
    });

    if (chunkTotal === null || headersByIdx.size < chunkTotal) return needMore();
    if (threshold === null || sharesByIdx.size < threshold) return needMore();

    // Reassemble header payload
    const ordered: HeaderChunkQr[] = [];
    for (let i = 0; i < chunkTotal; i++) {
      const h = headersByIdx.get(i);
      if (!h) return needMore();
      ordered.push(h);
    }
    const fullPayload = concat(...ordered.map((h) => h.payload));

    // Pick any T shares deterministically (lowest indices)
    const chosen = Array.from(sharesByIdx.values())
      .sort((a, b) => a.shareIdx - b.shareIdx)
      .slice(0, threshold);

    // Reconstruct KEM seed
    const kemSeed = combine(chosen.map((s) => s.share));
    if (kemSeed.length !== KEM_SEED_LEN) {
      kemSeed.fill(0);
      return { status: 'error', error: 'reconstructed seed has wrong length' };
    }

    const head = ordered[0]!;
    const { secretKey } = keygenFromSeed(head.kemAlg, kemSeed);
    kemSeed.fill(0);

    // Slice fullPayload: kem_ct || aead_nonce || aead_ct_and_tag
    const kemCtLen = kemCtLenFor(head.kemAlg);
    if (fullPayload.length < kemCtLen + AEAD_NONCE_LEN) {
      secretKey.fill(0);
      return { status: 'error', error: 'header payload too short' };
    }
    const kemCt = fullPayload.slice(0, kemCtLen);
    const nonce = fullPayload.slice(kemCtLen, kemCtLen + AEAD_NONCE_LEN);
    const aeadCt = fullPayload.slice(kemCtLen + AEAD_NONCE_LEN);

    const sharedSecret = decapsulate(head.kemAlg, secretKey, kemCt);
    secretKey.fill(0);

    const salt = bundleId;
    const argon2Params: Argon2Params = {
      t: head.argon2.tCost,
      m: 1 << head.argon2.memLog2KiB,
      p: head.argon2.parallelism,
    };
    if (head.flags.passphrase && !passphrase) {
      return {
        status: 'error',
        error: 'this bundle is passphrase-protected — provide a passphrase to decrypt',
      };
    }
    const aeadKey = buildAeadKey(
      sharedSecret,
      {
        ...DEFAULT_OPTIONS,
        kemAlg: head.kemAlg,
        aeadAlg: head.aeadAlg,
        kdfAlg: head.kdfAlg,
        threshold: head.t,
        shares: head.n,
        passphrase: head.flags.passphrase ? passphrase : undefined,
        argon2: argon2Params,
      },
      salt,
    );
    sharedSecret.fill(0);

    let pt: Uint8Array;
    try {
      pt = aeadDecrypt(head.aeadAlg, aeadKey, nonce, aeadCt);
    } catch (e) {
      aeadKey.fill(0);
      return {
        status: 'error',
        error:
          passphrase !== undefined
            ? 'decryption failed — wrong passphrase or tampered QR'
            : 'decryption failed — this bundle may require a passphrase, or the QR data is damaged',
      };
    }
    aeadKey.fill(0);

    return {
      status: 'ok',
      kind: 'secret',
      bundleId,
      plaintext: new TextDecoder().decode(pt),
      warnings: [],
      metadata: [],
    };
  } catch (e) {
    return {
      status: 'error',
      error: e instanceof Error ? e.message : String(e),
    };
  }
}

function decodeV2Parsed(parsed: ParsedQr[], opts: DecodeBundleOptions): DecodeBundleResult {
  if (parsed.some((p) => p.version !== 2 && p.version !== 3)) {
    return { status: 'error', error: 'decodeV2Parsed received non-v2/v3 QR payloads' };
  }

  const warnings = parsed.flatMap((p) => p.warnings ?? []);
  const groups = new Map<string, typeof parsed>();
  for (const p of parsed) {
    const k = hex(p.bundleId);
    const list = groups.get(k) ?? [];
    list.push(p);
    groups.set(k, list);
  }
  let best: typeof parsed = [];
  for (const [, list] of groups) {
    if (list.length > best.length) best = list;
  }
  const bundleId = best[0]!.bundleId;

  const headers = best.filter((p): p is HeaderChunkQr => p.kind === KIND_HEADER);
  const shares = best.filter((p): p is ShareQr => p.kind === KIND_SHARE);
  const headersByIdx = new Map<number, HeaderChunkQr>();
  for (const h of headers) headersByIdx.set(h.chunkIdx, h);
  const sharesByIdx = new Map<number, ShareQr>();
  for (const s of shares) sharesByIdx.set(s.shareIdx, s);

  const chunkTotal = headers[0]?.chunkTotal ?? null;
  const threshold = best.find((p) => p.kind === KIND_HEADER || p.kind === KIND_SHARE)?.t ?? null;
  const unverifiedMetadata = inspectShareMetadata(sharesByIdx);

  const needMore = (
    policyProgress?: PolicyProgress,
    lockedShares: LockedShare[] = [],
  ): DecodeBundleNeedMore => ({
    status: 'need-more',
    bundleId,
    headerChunksSeen: headersByIdx.size,
    headerChunksTotal: chunkTotal,
    sharesSeen: sharesByIdx.size,
    threshold,
    warnings,
    policyProgress,
    lockedShares,
    metadata: unverifiedMetadata,
  });

  if (chunkTotal === null || headersByIdx.size < chunkTotal) return needMore();

  const ordered: HeaderChunkQr[] = [];
  for (let i = 0; i < chunkTotal; i++) {
    const h = headersByIdx.get(i);
    if (!h) return needMore();
    ordered.push(h);
  }
  const firstHeader = ordered[0]!;
  const policyManifest = headerPolicyManifest(firstHeader);
  const policyCommitRaw = tlvValue(firstHeader, TLV_POLICY_COMMITMENT);
  const vdfParamsRaw = tlvValue(firstHeader, TLV_VDF_PARAMS);
  let vdfParams: VdfParams | null = null;
  if (vdfParamsRaw) {
    try {
      vdfParams = decodeVdfParams(vdfParamsRaw);
    } catch (e) {
      return { status: 'error', error: e instanceof Error ? e.message : String(e), warnings };
    }
  }
  const payloadKind = textFromTlv(firstHeader, TLV_PAYLOAD_FORMAT) ?? 'secret';
  const ptCommitRaw = tlvValue(firstHeader, TLV_PLAINTEXT_COMMITMENT);
  const decryptionProofRaw = tlvValue(firstHeader, TLV_DECRYPTION_PROOF);
  const vaultTreeRootRaw = tlvValue(firstHeader, TLV_VAULT_TREE_ROOT);
  const proofUsesPoseidon2Commitments = decryptionProofRaw
    ? canonicalProofUsesPoseidon2Commitments(decryptionProofRaw)
    : false;
  let zkDone = 0;
  const zkTotal =
    (policyCommitRaw ? 1 : 0) +
    (ptCommitRaw ? 1 : 0) +
    (payloadKind === 'vault-root' && vaultTreeRootRaw && opts.vaultBlob ? 1 : 0);
  const reportZk = (check: ZkProgressInfo['check'], status: ZkProgressInfo['status']) => {
    if (zkTotal === 0) return;
    const done = status === 'verifying' ? zkDone : Math.min(zkDone + 1, zkTotal);
    opts.onZkProgress?.({ check, status, done, total: zkTotal });
    if (status !== 'verifying') zkDone = done;
  };
  if (policyCommitRaw) {
    if (!proofUsesPoseidon2Commitments) {
      reportZk('policy', 'verifying');
      if (!verifyPolicyManifestCommitment(policyManifest, policyCommitRaw)) {
        reportZk('policy', 'tampered');
        return { status: 'error', error: 'policy manifest does not match published commitment', warnings };
      }
      reportZk('policy', 'verified');
    }
  }
  const fullPayload = concat(...ordered.map((h) => h.payload));
  let decryptionProof: DecryptionProofVerification | undefined;
  if (decryptionProofRaw && opts.verifyDecryptionProof !== false) {
    const proofInspection = inspectCanonicalDecryptionProofSync({
      proofRaw: decryptionProofRaw,
      firstHeader,
      fullPayload,
      payloadKind,
      policyCommitment: policyCommitRaw,
      plaintextCommitment: ptCommitRaw,
      vaultTreeRoot: vaultTreeRootRaw,
    });
    if (proofInspection.status === 'error') return { status: 'error', error: proofInspection.error, warnings };
    decryptionProof = proofInspection.decryptionProof;
    if (decryptionProof.status === 'unsupported') {
      warnings.push(`decryption proof scheme ${decryptionProof.schemeId} is unsupported`);
    } else if (decryptionProof.status !== 'verified') {
      return { status: 'error', error: `decryption proof ${decryptionProof.status}: ${decryptionProof.reason}`, warnings };
    }
  }

  const prepared = prepareV2Shares(
    sharesByIdx,
    opts.timeLockAdapter,
    vdfParams,
    bundleId,
    opts.onVdfProgress,
  );
  if (prepared.error) return { status: 'error', error: prepared.error, warnings };

  const recovered = recoverPolicySecret(policyManifest, prepared.shares);
  if (!recovered.secret) return needMore(recovered.progress, prepared.lockedShares);
  const kemSeed = recovered.secret;
  if (kemSeed.length !== KEM_SEED_LEN) {
    kemSeed.fill(0);
    return { status: 'error', error: 'reconstructed seed has wrong length', warnings };
  }

  if (policyCommitRaw && proofUsesPoseidon2Commitments) {
    reportZk('policy', 'verifying');
    if (
      !bytesEqual(
        bindPoseidon2Bn254PolicySeedCommitment({
          kemSeed,
          implementation: getDefaultPoseidon2Bn254Implementation(),
        }),
        policyCommitRaw,
      )
    ) {
      kemSeed.fill(0);
      reportZk('policy', 'tampered');
      return { status: 'error', error: 'policy seed does not match published proof-facing commitment', warnings };
    }
    reportZk('policy', 'verified');
  }

  const metadata = verifyShareMetadata(sharesByIdx, prepared.shares, kemSeed, bundleId, warnings);
  const decrypted = decryptHeaderPayload(firstHeader, fullPayload, bundleId, kemSeed, opts.passphrase);
  kemSeed.fill(0);
  if (decrypted.status === 'error') return { ...decrypted, warnings };

  if (ptCommitRaw) {
    reportZk('plaintext', 'verifying');
    const plaintextCommitmentOk = proofUsesPoseidon2Commitments
      ? payloadKind === 'vault-root' &&
        bytesEqual(
          bindPoseidon2Bn254VaultRootPlaintextCommitment({
            bundleId,
            vaultRootKey: decrypted.plaintextBytes,
            implementation: getDefaultPoseidon2Bn254Implementation(),
          }),
          ptCommitRaw,
        )
      : verifyPlaintextCommitment(ptCommitRaw, bundleId, decrypted.plaintextBytes);
    if (!plaintextCommitmentOk) {
      reportZk('plaintext', 'tampered');
      return { status: 'error', error: 'plaintext does not match published commitment', warnings };
    }
    reportZk('plaintext', 'verified');
  }

  if (payloadKind === 'vault-root') {
    if (decrypted.plaintextBytes.length !== AEAD_KEY_LEN) {
      return { status: 'error', error: 'vault root key has wrong length', warnings };
    }
    const vaultInfo = headerVaultInfo(firstHeader);
    if (!vaultInfo) return { status: 'error', error: 'vault bundle missing vault info', warnings };
    const vaultRootKey = decrypted.plaintextBytes;
    let vault: VaultPlaintext | undefined;
    if (opts.vaultBlob) {
      const blobInfo = inspectVaultBlob(opts.vaultBlob);
      if (hex(blobInfo.vaultId) !== hex(vaultInfo.vaultId)) {
        return { status: 'error', error: 'vault blob does not match QR vault id', warnings };
      }
      vault = decryptVault(vaultRootKey, opts.vaultBlob);
      if (vaultTreeRootRaw) {
        reportZk('vault-tree', 'verifying');
        const vaultRoot = proofUsesPoseidon2Commitments
          ? commitPoseidon2Bn254VaultTreeRoot({
              entries: vault.entries,
              implementation: getDefaultPoseidon2Bn254Implementation(),
            })
          : vaultTreeRoot(vault.entries);
        if (!bytesEqual(vaultRoot, vaultTreeRootRaw)) {
          reportZk('vault-tree', 'tampered');
          return { status: 'error', error: 'vault blob does not match published vault-tree root', warnings };
        }
        reportZk('vault-tree', 'verified');
      }
    }
    return {
      status: 'ok',
      kind: 'vault',
      bundleId,
      vaultRootKey,
      vaultId: vaultInfo.vaultId,
      vaultTreeRoot: vaultTreeRootRaw?.slice(),
      vault,
      warnings,
      decryptionProof,
      policyProgress: recovered.progress,
      metadata,
    };
  }

  if (payloadKind !== 'secret') return { status: 'error', error: `unsupported v2 payload kind ${payloadKind}`, warnings };
  return {
    status: 'ok',
    kind: 'secret',
    bundleId,
    plaintext: new TextDecoder().decode(decrypted.plaintextBytes),
    warnings,
    decryptionProof,
    policyProgress: recovered.progress,
    metadata,
  };
}

type PreparedV2Share = {
  shareIdx: number;
  components: ShareComponent[];
};

function headerPolicyManifest(header: HeaderChunkQr): PolicyManifest {
  const raw = tlvValue(header, TLV_POLICY_MANIFEST);
  if (!raw) throw new Error('v2 header missing policy manifest');
  return decodePolicyManifest(raw);
}

function headerVaultInfo(header: HeaderChunkQr) {
  const raw = tlvValue(header, TLV_VAULT_INFO);
  return raw ? decodeVaultInfo(raw) : null;
}

function inspectShareMetadata(sharesByIdx: Map<number, ShareQr>): DecodedShareMetadata[] {
  const out: DecodedShareMetadata[] = [];
  for (const share of sharesByIdx.values()) {
    const raw = tlvValue(share, TLV_SHARE_METADATA);
    if (!raw) continue;
    try {
      out.push({
        shareIdx: share.shareIdx,
        verification: { status: 'unverified', metadata: decodeShareMetadata(raw) },
        zkVerification: 'unverified',
      });
    } catch {
      out.push({
        shareIdx: share.shareIdx,
        verification: { status: 'tampered', metadata: {} },
        zkVerification: 'unverified',
      });
    }
  }
  return out.sort((a, b) => a.shareIdx - b.shareIdx);
}

function verifyShareMetadata(
  sharesByIdx: Map<number, ShareQr>,
  preparedShares: PreparedV2Share[],
  kemSeed: Uint8Array,
  bundleId: Uint8Array,
  warnings: string[],
): DecodedShareMetadata[] {
  const key = deriveMetadataKey(kemSeed, bundleId);
  const componentsByShareIdx = new Map(preparedShares.map((share) => [share.shareIdx, share.components]));
  const out: DecodedShareMetadata[] = [];
  for (const share of sharesByIdx.values()) {
    const raw = tlvValue(share, TLV_SHARE_METADATA);
    if (!raw) continue;
    const components = componentsByShareIdx.get(share.shareIdx);
    const zkVerification = verifyShareZkStatus(share, components, key, bundleId, warnings);
    let metadata: ShareMetadata;
    try {
      metadata = decodeShareMetadata(raw);
    } catch {
      out.push({
        shareIdx: share.shareIdx,
        verification: { status: 'tampered', metadata: {} },
        zkVerification,
      });
      continue;
    }
    const mac = tlvValue(share, TLV_SHARE_METADATA_MAC);
    if (!components) {
      out.push({
        shareIdx: share.shareIdx,
        verification: { status: 'unverified', metadata },
        zkVerification,
      });
      continue;
    }
    const verified =
      !!mac &&
      verifyMetadataMac(
        key,
        metadata,
        {
          bundleId,
          shareIdx: share.shareIdx,
          componentIds: components.map((component) => component.id),
        },
        mac,
      );
    out.push({
      shareIdx: share.shareIdx,
      verification: verified ? { status: 'verified', metadata } : { status: 'tampered', metadata },
      zkVerification,
    });
  }
  key.fill(0);
  return out.sort((a, b) => a.shareIdx - b.shareIdx);
}

function verifyShareZkStatus(
  share: ShareQr,
  components: ShareComponent[] | undefined,
  metadataKey: Uint8Array,
  bundleId: Uint8Array,
  warnings: string[],
): ZkShareVerification {
  const proofRaw = tlvValue(share, TLV_SHARE_COMMIT_PROOF);
  if (!proofRaw || !components) return 'unverified';
  try {
    if (verifyShareCommitProof(proofRaw, components, metadataKey, bundleId, share.shareIdx)) {
      return 'verified';
    }
  } catch {
    // Fall through to a tamper warning.
  }
  warnings.push(`share ${share.shareIdx} commitment proof failed verification`);
  return 'tampered';
}

function prepareV2Shares(
  sharesByIdx: Map<number, ShareQr>,
  timeLockAdapter?: TimeLockAdapter,
  vdfParams?: VdfParams | null,
  bundleId?: Uint8Array,
  onVdfProgress?: (info: VdfProgressInfo) => void,
): { shares: PreparedV2Share[]; lockedShares: LockedShare[]; error?: string } {
  const shares: PreparedV2Share[] = [];
  const lockedShares: LockedShare[] = [];
  const vdfShareTotal = Array.from(sharesByIdx.values()).filter((share) => !!tlvValue(share, TLV_VDF_LOCK)).length;
  let vdfShareOrdinal = 0;
  for (const share of sharesByIdx.values()) {
    let payload = share.share;
    const vdfLockRaw = tlvValue(share, TLV_VDF_LOCK);
    if (vdfLockRaw) {
      vdfShareOrdinal++;
      if (!vdfParams) {
        return { shares, lockedShares, error: 'share is VDF-locked but bundle has no VDF parameters' };
      }
      try {
        const lock = decodeVdfShareLock(vdfLockRaw);
        const proofRaw = tlvValue(share, TLV_VDF_PROOF);
        const proof = proofRaw ? decodeVdfProof(proofRaw) : undefined;
        if (!bundleId) return { shares, lockedShares, error: 'cannot verify VDF share generator without bundle id' };
        const expectedG = hashToForm(concat(bundleId, new Uint8Array([share.shareIdx])), vdfParams.delta);
        if (!formsEqual(lock.g, expectedG)) {
          return {
            shares,
            lockedShares,
            error: `VDF lock for share ${share.shareIdx} does not match bundle-derived generator`,
          };
        }
        payload = vdfUnlockShare(
          payload,
          vdfParams,
          lock,
          (done, total) => {
            onVdfProgress?.({
              phase: 'unlock',
              shareIdx: share.shareIdx,
              shareOrdinal: vdfShareOrdinal,
              shareTotal: vdfShareTotal,
              done,
              total,
            });
          },
          proof,
        );
      } catch (e) {
        return {
          shares,
          lockedShares,
          error: e instanceof Error ? e.message : 'failed to unlock VDF share',
        };
      }
    }
    const timeLockRaw = tlvValue(share, TLV_TIMELOCK);
    if (timeLockRaw) {
      let timeLock: TimeLockInfo;
      try {
        timeLock = decodeTimeLockInfo(timeLockRaw);
      } catch (e) {
        return { shares, lockedShares, error: e instanceof Error ? e.message : String(e) };
      }
      if (!timeLockAdapter) {
        lockedShares.push({ shareIdx: share.shareIdx, timeLock });
        continue;
      }
      try {
        payload = unlockSharePayload(payload, timeLock, timeLockAdapter);
      } catch (e) {
        return {
          shares,
          lockedShares,
          error: e instanceof Error ? e.message : 'failed to unlock time-locked share',
        };
      }
    }
    try {
      shares.push({ shareIdx: share.shareIdx, components: decodeShareComponents(payload) });
    } catch (e) {
      return { shares, lockedShares, error: e instanceof Error ? e.message : String(e) };
    }
  }
  return { shares, lockedShares };
}

type HeaderPayloadParts = {
  kemCt: Uint8Array;
  nonce: Uint8Array;
  aeadCt: Uint8Array;
};

type CanonicalProofInspection =
  | { status: 'ok'; decryptionProof: DecryptionProofVerification }
  | { status: 'error'; error: string };

type CanonicalProofContext = {
  firstHeader: HeaderChunkQr;
  fullPayload: Uint8Array;
  proofRaw?: Uint8Array;
  payloadKind: string;
  policyCommitment?: Uint8Array;
  plaintextCommitment?: Uint8Array;
  vaultTreeRoot?: Uint8Array;
};

function inspectCanonicalDecryptionProofSync(args: {
  proofRaw: Uint8Array;
  firstHeader: HeaderChunkQr;
  fullPayload: Uint8Array;
  payloadKind: string;
  policyCommitment?: Uint8Array;
  plaintextCommitment?: Uint8Array;
  vaultTreeRoot?: Uint8Array;
}): CanonicalProofInspection {
  const prepared = prepareCanonicalDecryptionProofPublicInputs(args);
  if (prepared.status === 'error') return prepared;
  if (!prepared.publicInputs) {
    return {
      status: 'ok',
      decryptionProof: { status: 'unsupported', schemeId: prepared.schemeId },
    };
  }
  return {
    status: 'ok',
    decryptionProof: { status: 'unsupported', schemeId: prepared.schemeId },
  };
}

function canonicalProofUsesPoseidon2Commitments(proofRaw: Uint8Array): boolean {
  try {
    return proofFacingCommitmentsUsePoseidon2Bn254(
      decodeCanonicalDecryptionProofEnvelope(proofRaw).relationDigest,
    );
  } catch {
    return false;
  }
}

async function inspectCanonicalDecryptionProofAsync(
  parsed: ParsedQr[],
  opts: DecodeBundleAsyncOptions,
): Promise<CanonicalProofInspection | null> {
  const context = canonicalProofContextFromParsed(parsed);
  if (!context || !context.proofRaw) return null;
  const prepared = prepareCanonicalDecryptionProofPublicInputs({
    proofRaw: context.proofRaw,
    firstHeader: context.firstHeader,
    fullPayload: context.fullPayload,
    payloadKind: context.payloadKind,
    policyCommitment: context.policyCommitment,
    plaintextCommitment: context.plaintextCommitment,
    vaultTreeRoot: context.vaultTreeRoot,
  });
  if (prepared.status === 'error') return prepared;
  if (!prepared.publicInputs) {
    return {
      status: 'ok',
      decryptionProof: { status: 'unsupported', schemeId: prepared.schemeId },
    };
  }

  const result = await verifyDecryptionProofEnvelopeV1({
    envelope: prepared.envelope,
    publicInputs: prepared.publicInputs,
    verifiers: opts.decryptionProofV1Verifiers,
    signal: opts.signal,
  });
  if (result.status === 'verified') {
    return {
      status: 'ok',
      decryptionProof: { status: 'verified', schemeId: prepared.schemeId },
    };
  }
  if (result.status === 'unsupported') {
    return {
      status: 'ok',
      decryptionProof: { status: 'unsupported', schemeId: prepared.schemeId },
    };
  }
  return { status: 'error', error: `decryption proof failed: ${result.reason}` };
}

function prepareCanonicalDecryptionProofPublicInputs(args: {
  proofRaw: Uint8Array;
  firstHeader: HeaderChunkQr;
  fullPayload: Uint8Array;
  payloadKind: string;
  policyCommitment?: Uint8Array;
  plaintextCommitment?: Uint8Array;
  vaultTreeRoot?: Uint8Array;
}):
  | {
      status: 'ok';
      schemeId: number;
      envelope: ReturnType<typeof decodeCanonicalDecryptionProofEnvelope>;
      publicInputs?: DecryptionProofPublicInputsV1;
    }
  | { status: 'error'; error: string } {
  try {
    const envelope = decodeCanonicalDecryptionProofEnvelope(args.proofRaw);
    if (!proofFacingCommitmentsUsePoseidon2Bn254(envelope.relationDigest)) {
      return { status: 'ok', schemeId: envelope.schemeId, envelope };
    }
    if (!args.policyCommitment) return { status: 'error', error: 'decryption proof requires a policy commitment' };
    if (!args.plaintextCommitment) return { status: 'error', error: 'decryption proof requires a plaintext commitment' };
    const publicInputs = buildDecryptionProofPublicInputsFromDecodedHeaderV1({
      firstHeader: args.firstHeader,
      fullHeaderPayload: args.fullPayload,
      payloadKind: args.payloadKind,
      policyCommitment: args.policyCommitment,
      plaintextCommitment: args.plaintextCommitment,
      vaultTreeRoot: args.vaultTreeRoot,
    });
    const transcriptDigest = digestDecryptionProofPublicInputsV1(publicInputs);
    if (!bytesEqual(envelope.transcriptDigest, transcriptDigest)) {
      return { status: 'error', error: 'decryption proof transcript mismatch' };
    }
    return { status: 'ok', schemeId: envelope.schemeId, envelope, publicInputs };
  } catch (e) {
    return { status: 'error', error: e instanceof Error ? e.message : String(e) };
  }
}

function canonicalProofContextFromParsed(parsed: ParsedQr[]): CanonicalProofContext | null {
  if (parsed.length === 0) return null;
  if (parsed.some((p) => p.version !== VERSION_V2 && p.version !== VERSION_V3)) return null;

  const groups = new Map<string, ParsedQr[]>();
  for (const p of parsed) {
    const key = hex(p.bundleId);
    const list = groups.get(key) ?? [];
    list.push(p);
    groups.set(key, list);
  }
  let best: ParsedQr[] = [];
  for (const [, list] of groups) {
    if (list.length > best.length) best = list;
  }

  const headers = best.filter((p): p is HeaderChunkQr => p.kind === KIND_HEADER);
  const headersByIdx = new Map<number, HeaderChunkQr>();
  for (const header of headers) headersByIdx.set(header.chunkIdx, header);
  const chunkTotal = headers[0]?.chunkTotal ?? null;
  if (chunkTotal === null || headersByIdx.size < chunkTotal) return null;

  const ordered: HeaderChunkQr[] = [];
  for (let i = 0; i < chunkTotal; i++) {
    const header = headersByIdx.get(i);
    if (!header) return null;
    ordered.push(header);
  }
  const firstHeader = ordered[0]!;
  return {
    firstHeader,
    fullPayload: concat(...ordered.map((header) => header.payload)),
    proofRaw: tlvValue(firstHeader, TLV_DECRYPTION_PROOF),
    payloadKind: textFromTlv(firstHeader, TLV_PAYLOAD_FORMAT) ?? 'secret',
    policyCommitment: tlvValue(firstHeader, TLV_POLICY_COMMITMENT),
    plaintextCommitment: tlvValue(firstHeader, TLV_PLAINTEXT_COMMITMENT),
    vaultTreeRoot: tlvValue(firstHeader, TLV_VAULT_TREE_ROOT),
  };
}

function splitHeaderPayload(head: HeaderChunkQr, fullPayload: Uint8Array): HeaderPayloadParts | DecodeError {
  const kemCtLen = kemCtLenFor(head.kemAlg);
  if (fullPayload.length < kemCtLen + AEAD_NONCE_LEN) {
    return { status: 'error', error: 'header payload too short' };
  }
  return {
    kemCt: fullPayload.slice(0, kemCtLen),
    nonce: fullPayload.slice(kemCtLen, kemCtLen + AEAD_NONCE_LEN),
    aeadCt: fullPayload.slice(kemCtLen + AEAD_NONCE_LEN),
  };
}

function decryptHeaderPayload(
  head: HeaderChunkQr,
  fullPayload: Uint8Array,
  bundleId: Uint8Array,
  kemSeed: Uint8Array,
  passphrase?: string,
): { status: 'ok'; plaintextBytes: Uint8Array } | DecodeError {
  const parts = splitHeaderPayload(head, fullPayload);
  if ('status' in parts) return parts;

  const { secretKey } = keygenFromSeed(head.kemAlg, kemSeed);
  const sharedSecret = decapsulate(head.kemAlg, secretKey, parts.kemCt);
  secretKey.fill(0);

  const argon2Params: Argon2Params = {
    t: head.argon2.tCost,
    m: 1 << head.argon2.memLog2KiB,
    p: head.argon2.parallelism,
  };
  if (head.flags.passphrase && !passphrase) {
    sharedSecret.fill(0);
    return {
      status: 'error',
      error: 'this bundle is passphrase-protected — provide a passphrase to decrypt',
    };
  }
  const aeadKey = buildAeadKey(
    sharedSecret,
    {
      ...DEFAULT_OPTIONS,
      kemAlg: head.kemAlg,
      aeadAlg: head.aeadAlg,
      kdfAlg: head.kdfAlg,
      threshold: head.t,
      shares: head.n,
      passphrase: head.flags.passphrase ? passphrase : undefined,
      argon2: argon2Params,
    },
    bundleId,
  );
  sharedSecret.fill(0);

  try {
    const plaintextBytes = aeadDecrypt(head.aeadAlg, aeadKey, parts.nonce, parts.aeadCt);
    aeadKey.fill(0);
    return { status: 'ok', plaintextBytes };
  } catch {
    aeadKey.fill(0);
    return {
      status: 'error',
      error:
        passphrase !== undefined
          ? 'decryption failed — wrong passphrase or tampered QR'
          : 'decryption failed — this bundle may require a passphrase, or the QR data is damaged',
    };
  }
}

function tlvValue(qr: HeaderChunkQr | ShareQr, tagId: number): Uint8Array | undefined {
  return qr.extensions?.find((extension) => extension.tagId === tagId)?.value;
}

function textFromTlv(qr: HeaderChunkQr | ShareQr, tagId: number): string | undefined {
  const raw = tlvValue(qr, tagId);
  return raw ? new TextDecoder().decode(raw) : undefined;
}

function textBytes(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function copyVaultEntry(entry: VaultEntry): VaultEntry {
  const copy: VaultEntry = {
    id: entry.id,
    name: entry.name,
    data: entry.data.slice(),
  };
  if (entry.contentType) copy.contentType = entry.contentType;
  return copy;
}

function copyMerkleProof(proof: MerkleProof): MerkleProof {
  return {
    index: proof.index,
    leafCount: proof.leafCount,
    siblings: proof.siblings.map((sibling) => sibling.slice()),
  };
}

const SHARE_COMMIT_PROOF_LEN = POINT_LEN + SCHNORR_PROOF_LEN;

function shareIdxBytes(shareIdx: number): Uint8Array {
  return new Uint8Array([shareIdx & 0xff]);
}

function shareCommitContext(bundleId: Uint8Array, shareIdx: number): Uint8Array {
  return concat(bundleId, shareIdxBytes(shareIdx));
}

function encodeShareCommitProof(
  componentPayload: Uint8Array,
  metadataKey: Uint8Array,
  bundleId: Uint8Array,
  shareIdx: number,
): Uint8Array {
  const value = hashToScalar('share-value', componentPayload);
  const blinding = hashToScalar('share-blinding', metadataKey, shareIdxBytes(shareIdx));
  const commitment = pedersenCommit(value, blinding);
  const proof = schnorrProveCommit(value, blinding, commitment, shareCommitContext(bundleId, shareIdx));
  return concat(commitmentToBytes(commitment), encodeSchnorrProof(proof));
}

function verifyShareCommitProof(
  raw: Uint8Array,
  components: ShareComponent[],
  metadataKey: Uint8Array,
  bundleId: Uint8Array,
  shareIdx: number,
): boolean {
  if (raw.length !== SHARE_COMMIT_PROOF_LEN) {
    throw new Error(`share commitment proof must be ${SHARE_COMMIT_PROOF_LEN} bytes`);
  }
  const commitment = commitmentFromBytes(raw.slice(0, POINT_LEN));
  const proof = decodeSchnorrProof(raw.slice(POINT_LEN));
  const componentPayload = encodeShareComponents(components);
  const value = hashToScalar('share-value', componentPayload);
  const blinding = hashToScalar('share-blinding', metadataKey, shareIdxBytes(shareIdx));
  const expected = pedersenCommit(value, blinding);
  return (
    schnorrVerifyCommit(commitment, proof, shareCommitContext(bundleId, shareIdx)) &&
    bytesEqual(commitmentToBytes(commitment), commitmentToBytes(expected))
  );
}

function kemCtLenFor(alg: KemAlg): number {
  switch (alg) {
    case 'ml-kem-512':
      return 768;
    case 'ml-kem-768':
      return 1088;
    case 'ml-kem-1024':
      return 1568;
  }
}

function hex(b: Uint8Array): string {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}

function fromHex(value: string): Uint8Array {
  if (typeof value !== 'string' || value.length % 2 !== 0) throw new Error('invalid hex length');
  if (!/^[0-9a-fA-F]*$/.test(value)) throw new Error('invalid hex byte');
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    out[i] = byte;
  }
  return out;
}

export function inspectQrKind(payload: string): 'header' | 'share' | 'unknown' {
  try {
    const p = parse(fromBase45(payload));
    return p.kind === KIND_HEADER ? 'header' : p.kind === KIND_SHARE ? 'share' : 'unknown';
  } catch {
    return 'unknown';
  }
}

export type { MetadataVerification, ShareMetadata } from './metadata';
export type { Custodian, PolicyManifest, PolicyNode, PolicyProgress, ShareComponent } from './policy';
export {
  decryptVault,
  encryptVault,
  inspectVaultBlob,
  updateVaultEntries,
  VAULT_FORMAT_VERSION,
  type DecryptVaultOptions,
  type VaultEntry,
  type VaultInfo,
  type VaultPlaintext,
} from './vault';
export type { MerkleProof } from './zk/merkle';
export {
  DRAND_QUICKNET_CHAIN_HASH,
  TIMELOCK_SECURITY_NOTICE,
  type TimeLockAdapter,
  type TimeLockInfo,
  type TimeLockOptions,
} from './timelock';
export { fromBase45, toBase45, parse };
