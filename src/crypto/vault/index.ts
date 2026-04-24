import { aeadDecrypt, aeadEncrypt, AEAD_KEY_LEN, AEAD_NONCE_LEN } from '../aead';

export const VAULT_FORMAT_VERSION = 1;
export const VAULT_BLOB_MAGIC = 'SSSSVAULT';

export type VaultEntry = {
  id: string;
  name: string;
  data: Uint8Array;
  contentType?: string;
};

export type VaultPlaintext = {
  vaultId: Uint8Array;
  entries: VaultEntry[];
};

export type VaultInfo = {
  vaultId: Uint8Array;
  formatVersion: number;
};

type VaultManifest = {
  entries: Array<{ id: string; name: string; contentType?: string }>;
};

type VaultBlobJson = {
  magic: typeof VAULT_BLOB_MAGIC;
  version: typeof VAULT_FORMAT_VERSION;
  vaultId: string;
  manifest: { nonce: string; ciphertext: string };
  entries: Array<{ id: string; nonce: string; ciphertext: string }>;
};

const enc = new TextEncoder();
const dec = new TextDecoder();

export function generateVaultRootKey(rng: (n: number) => Uint8Array = randomBytes): Uint8Array {
  return rng(AEAD_KEY_LEN);
}

export function createVaultBlob(
  rootKey: Uint8Array,
  entries: VaultEntry[],
  opts: { vaultId?: Uint8Array; rng?: (n: number) => Uint8Array } = {},
): { vaultId: Uint8Array; blob: Uint8Array } {
  const rng = opts.rng ?? randomBytes;
  const vaultId = opts.vaultId ?? rng(16);
  const blob = encryptVault(rootKey, { vaultId, entries }, rng);
  return { vaultId, blob };
}

export function encryptVault(
  rootKey: Uint8Array,
  vault: VaultPlaintext,
  rng: (n: number) => Uint8Array = randomBytes,
): Uint8Array {
  assertRootKey(rootKey);
  if (vault.vaultId.length !== 16) throw new Error('vaultId must be 16 bytes');
  const manifest: VaultManifest = {
    entries: vault.entries.map((entry) => {
      const item: VaultManifest['entries'][number] = { id: entry.id, name: entry.name };
      if (entry.contentType) item.contentType = entry.contentType;
      return item;
    }),
  };
  const manifestNonce = rng(AEAD_NONCE_LEN);
  const manifestCiphertext = aeadEncrypt(
    'aes-256-gcm',
    rootKey,
    manifestNonce,
    enc.encode(JSON.stringify(manifest)),
  );
  const encryptedEntries = vault.entries.map((entry) => {
    const nonce = rng(AEAD_NONCE_LEN);
    return {
      id: entry.id,
      nonce: hex(nonce),
      ciphertext: hex(aeadEncrypt('aes-256-gcm', rootKey, nonce, entry.data)),
    };
  });
  const json: VaultBlobJson = {
    magic: VAULT_BLOB_MAGIC,
    version: VAULT_FORMAT_VERSION,
    vaultId: hex(vault.vaultId),
    manifest: { nonce: hex(manifestNonce), ciphertext: hex(manifestCiphertext) },
    entries: encryptedEntries,
  };
  return enc.encode(JSON.stringify(json));
}

export function decryptVault(rootKey: Uint8Array, blob: Uint8Array): VaultPlaintext {
  assertRootKey(rootKey);
  const json = parseVaultBlob(blob);
  const vaultId = fromHex(json.vaultId);
  const manifestPlaintext = aeadDecrypt(
    'aes-256-gcm',
    rootKey,
    fromHex(json.manifest.nonce),
    fromHex(json.manifest.ciphertext),
  );
  const manifest = JSON.parse(dec.decode(manifestPlaintext)) as VaultManifest;
  const encryptedById = new Map(json.entries.map((entry) => [entry.id, entry]));
  const entries = manifest.entries.map((manifestEntry) => {
    const encrypted = encryptedById.get(manifestEntry.id);
    if (!encrypted) throw new Error(`vault entry ${manifestEntry.id} missing ciphertext`);
    const item: VaultEntry = {
      id: manifestEntry.id,
      name: manifestEntry.name,
      data: aeadDecrypt(
        'aes-256-gcm',
        rootKey,
        fromHex(encrypted.nonce),
        fromHex(encrypted.ciphertext),
      ),
    };
    if (manifestEntry.contentType) item.contentType = manifestEntry.contentType;
    return item;
  });
  return { vaultId, entries };
}

export function inspectVaultBlob(blob: Uint8Array): VaultInfo {
  const json = parseVaultBlob(blob);
  return { vaultId: fromHex(json.vaultId), formatVersion: json.version };
}

export function updateVaultEntries(
  rootKey: Uint8Array,
  blob: Uint8Array,
  entries: VaultEntry[],
  rng?: (n: number) => Uint8Array,
): Uint8Array {
  const current = decryptVault(rootKey, blob);
  return encryptVault(rootKey, { vaultId: current.vaultId, entries }, rng);
}

export function encodeVaultInfo(info: VaultInfo): Uint8Array {
  return enc.encode(
    JSON.stringify({
      vaultId: hex(info.vaultId),
      formatVersion: info.formatVersion,
    }),
  );
}

export function decodeVaultInfo(raw: Uint8Array): VaultInfo {
  const parsed = JSON.parse(dec.decode(raw)) as { vaultId?: string; formatVersion?: number };
  if (typeof parsed.vaultId !== 'string') throw new Error('vault info missing vaultId');
  if (parsed.formatVersion !== VAULT_FORMAT_VERSION) throw new Error('unsupported vault format version');
  return { vaultId: fromHex(parsed.vaultId), formatVersion: parsed.formatVersion };
}

function parseVaultBlob(blob: Uint8Array): VaultBlobJson {
  const parsed = JSON.parse(dec.decode(blob)) as VaultBlobJson;
  if (parsed.magic !== VAULT_BLOB_MAGIC) throw new Error('not a .ssssvault blob');
  if (parsed.version !== VAULT_FORMAT_VERSION) throw new Error('unsupported vault blob version');
  return parsed;
}

function assertRootKey(rootKey: Uint8Array): void {
  if (rootKey.length !== AEAD_KEY_LEN) throw new Error(`vault root key must be ${AEAD_KEY_LEN} bytes`);
}

function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  crypto.getRandomValues(out);
  return out;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0) throw new Error('invalid hex length');
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) throw new Error('invalid hex byte');
    out[i] = byte;
  }
  return out;
}
