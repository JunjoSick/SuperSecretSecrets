import { gcm } from '@noble/ciphers/aes.js';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

export type AeadAlg = 'aes-256-gcm' | 'chacha20-poly1305';

export const AEAD_ALG_ID: Record<AeadAlg, number> = {
  'aes-256-gcm': 0,
  'chacha20-poly1305': 1,
};

export const AEAD_ALG_NAME: Record<number, AeadAlg> = {
  0: 'aes-256-gcm',
  1: 'chacha20-poly1305',
};

export const AEAD_KEY_LEN = 32;
export const AEAD_NONCE_LEN = 12;
export const AEAD_TAG_LEN = 16;

function cipher(alg: AeadAlg, key: Uint8Array, nonce: Uint8Array) {
  if (key.length !== AEAD_KEY_LEN) throw new Error(`AEAD key must be ${AEAD_KEY_LEN} bytes`);
  if (nonce.length !== AEAD_NONCE_LEN) throw new Error(`AEAD nonce must be ${AEAD_NONCE_LEN} bytes`);
  switch (alg) {
    case 'aes-256-gcm':
      return gcm(key, nonce);
    case 'chacha20-poly1305':
      return chacha20poly1305(key, nonce);
  }
}

export function aeadEncrypt(
  alg: AeadAlg,
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  return cipher(alg, key, nonce).encrypt(plaintext);
}

export function aeadDecrypt(
  alg: AeadAlg,
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
): Uint8Array {
  return cipher(alg, key, nonce).decrypt(ciphertext);
}
