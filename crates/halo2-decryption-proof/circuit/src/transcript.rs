//! TLV codec for the decryption proof public inputs blob produced by
//! `encodeDecryptionProofPublicInputsV1` in
//! `src/crypto/zk/decryption-proof-transcript.ts`.
//!
//! The Halo2 verifier WASM wrapper receives the encoded blob as input and
//! needs to extract the BN254 instance values used by the circuit
//! (currently `bundle_id` and `plaintext_commitment`). The decoder here is
//! deliberately strict: it rejects out-of-order tags, trailing bytes, and
//! any field with the wrong length, so the wrapper cannot accept a blob
//! that disagrees with the TS encoder.

use core::convert::TryInto;
use sha2::{Digest, Sha256};

pub const TRANSCRIPT_DOMAIN: &str = "SSS/v3/decryption-proof/public-inputs/v1";
pub const TRANSCRIPT_VERSION: u8 = 1;

pub const BUNDLE_ID_BYTES: usize = 8;
pub const COMMITMENT_BYTES: usize = 32;
pub const ALGORITHM_TUPLE_BYTES: usize = 5;
pub const ARGON2_TUPLE_BYTES: usize = 12;

pub const ML_KEM_768_CIPHERTEXT_BYTES: usize = 1088;
pub const AES_256_GCM_NONCE_BYTES: usize = 12;
pub const AES_256_GCM_TAG_BYTES: usize = 16;

pub const PROOF_KEM_ID_ML_KEM_768: u8 = 0x01;
pub const PROOF_KDF_ID_HKDF_SHA256: u8 = 0x01;
pub const PROOF_AEAD_ID_AES_256_GCM: u8 = 0x01;
pub const PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254: u8 = 0x01;

pub const PAYLOAD_KIND_VAULT_ROOT: &str = "vault-root";

#[derive(Debug)]
pub enum TranscriptError {
    Truncated(&'static str),
    DomainMismatch,
    UnsupportedVersion,
    DuplicateOrOutOfOrderField(u8),
    MissingField(u8),
    TrailingBytes,
    InvalidPayloadKind,
    InvalidAlgorithmTuple,
    InvalidArgon2Tuple,
    InvalidPassphraseFlag,
    InvalidLength(&'static str),
    PassphraseFlagSet,
    NonZeroArgon2Param,
}

impl core::fmt::Display for TranscriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated(label) => write!(f, "truncated {label}"),
            Self::DomainMismatch => write!(f, "unsupported decryption proof transcript domain"),
            Self::UnsupportedVersion => {
                write!(f, "unsupported decryption proof transcript version")
            }
            Self::DuplicateOrOutOfOrderField(tag) => write!(
                f,
                "duplicate or out-of-order decryption proof transcript field 0x{tag:02x}"
            ),
            Self::MissingField(tag) => {
                write!(f, "missing decryption proof transcript field 0x{tag:02x}")
            }
            Self::TrailingBytes => write!(f, "trailing bytes after decryption proof transcript"),
            Self::InvalidPayloadKind => {
                write!(f, "decryption proof payload kind must be vault-root")
            }
            Self::InvalidAlgorithmTuple => {
                write!(f, "decryption proof algorithm tuple must be 5 bytes")
            }
            Self::InvalidArgon2Tuple => write!(f, "decryption proof Argon2 tuple must be 12 bytes"),
            Self::InvalidPassphraseFlag => {
                write!(f, "decryption proof passphrase flag must be false")
            }
            Self::InvalidLength(label) => write!(f, "decryption proof {label} has wrong length"),
            Self::PassphraseFlagSet => write!(f, "decryption proof passphrase flag must be false"),
            Self::NonZeroArgon2Param => {
                write!(
                    f,
                    "no-passphrase decryption proof relation requires zero Argon2 params"
                )
            }
        }
    }
}

impl std::error::Error for TranscriptError {}

#[derive(Debug)]
pub struct DecryptionProofPublicInputsV1<'a> {
    pub bundle_id: &'a [u8; BUNDLE_ID_BYTES],
    pub kem_alg_id: u8,
    pub kdf_alg_id: u8,
    pub aead_alg_id: u8,
    pub commitment_hash_id: u8,
    pub policy_commitment: &'a [u8; COMMITMENT_BYTES],
    pub plaintext_commitment: &'a [u8; COMMITMENT_BYTES],
    pub vault_tree_root: &'a [u8; COMMITMENT_BYTES],
    pub kem_ciphertext: &'a [u8; ML_KEM_768_CIPHERTEXT_BYTES],
    pub aead_nonce: &'a [u8; AES_256_GCM_NONCE_BYTES],
    pub aead_ciphertext_and_tag: &'a [u8],
}

pub fn decode_public_inputs(
    encoded: &[u8],
) -> Result<DecryptionProofPublicInputsV1<'_>, TranscriptError> {
    let mut reader = Reader::new(encoded);
    let domain_len = reader.read_u16("transcript domain length")? as usize;
    let domain = reader.read_slice(domain_len, "transcript domain")?;
    if domain != TRANSCRIPT_DOMAIN.as_bytes() {
        return Err(TranscriptError::DomainMismatch);
    }
    let version = reader.read_u8("transcript version")?;
    if version != TRANSCRIPT_VERSION {
        return Err(TranscriptError::UnsupportedVersion);
    }

    let bundle_id_field = reader.read_field(0x01)?;
    let bundle_id: &[u8; BUNDLE_ID_BYTES] = bundle_id_field
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("bundleId"))?;

    let payload_kind = reader.read_field(0x02)?;
    if payload_kind != PAYLOAD_KIND_VAULT_ROOT.as_bytes() {
        return Err(TranscriptError::InvalidPayloadKind);
    }

    let algorithm_tuple = reader.read_field(0x03)?;
    if algorithm_tuple.len() != ALGORITHM_TUPLE_BYTES {
        return Err(TranscriptError::InvalidAlgorithmTuple);
    }
    if algorithm_tuple[0] != PROOF_KEM_ID_ML_KEM_768
        || algorithm_tuple[1] != PROOF_KDF_ID_HKDF_SHA256
        || algorithm_tuple[2] != PROOF_AEAD_ID_AES_256_GCM
        || algorithm_tuple[3] != PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254
    {
        return Err(TranscriptError::InvalidAlgorithmTuple);
    }
    if algorithm_tuple[4] != 0 {
        return Err(TranscriptError::PassphraseFlagSet);
    }

    let argon2_tuple = reader.read_field(0x04)?;
    if argon2_tuple.len() != ARGON2_TUPLE_BYTES {
        return Err(TranscriptError::InvalidArgon2Tuple);
    }
    let argon2_t = u32::from_be_bytes(argon2_tuple[0..4].try_into().unwrap());
    let argon2_m = u32::from_be_bytes(argon2_tuple[4..8].try_into().unwrap());
    let argon2_p = u32::from_be_bytes(argon2_tuple[8..12].try_into().unwrap());
    if argon2_t != 0 || argon2_m != 0 || argon2_p != 0 {
        return Err(TranscriptError::NonZeroArgon2Param);
    }

    let policy_commitment: &[u8; COMMITMENT_BYTES] = reader
        .read_field(0x05)?
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("policyCommitment"))?;
    let plaintext_commitment: &[u8; COMMITMENT_BYTES] = reader
        .read_field(0x06)?
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("plaintextCommitment"))?;
    let vault_tree_root: &[u8; COMMITMENT_BYTES] = reader
        .read_field(0x07)?
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("vaultTreeRoot"))?;
    let kem_ciphertext: &[u8; ML_KEM_768_CIPHERTEXT_BYTES] = reader
        .read_field(0x08)?
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("kemCiphertext"))?;
    let aead_nonce: &[u8; AES_256_GCM_NONCE_BYTES] = reader
        .read_field(0x09)?
        .try_into()
        .map_err(|_| TranscriptError::InvalidLength("aeadNonce"))?;
    let aead_ciphertext_and_tag = reader.read_field(0x0a)?;
    if aead_ciphertext_and_tag.len() < AES_256_GCM_TAG_BYTES {
        return Err(TranscriptError::InvalidLength("aeadCiphertextAndTag"));
    }

    if !reader.is_empty() {
        return Err(TranscriptError::TrailingBytes);
    }

    Ok(DecryptionProofPublicInputsV1 {
        bundle_id,
        kem_alg_id: algorithm_tuple[0],
        kdf_alg_id: algorithm_tuple[1],
        aead_alg_id: algorithm_tuple[2],
        commitment_hash_id: algorithm_tuple[3],
        policy_commitment,
        plaintext_commitment,
        vault_tree_root,
        kem_ciphertext,
        aead_nonce,
        aead_ciphertext_and_tag,
    })
}

/// SHA-256(encoded_public_inputs) — equivalent to the TS
/// `digestDecryptionProofPublicInputsV1`. The wasm verifier wrapper checks
/// this matches the envelope's `transcriptDigest` before invoking halo2.
pub fn transcript_digest(encoded: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(encoded);
    let out = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    bytes
}

struct Reader<'a> {
    buf: &'a [u8],
    cursor: usize,
    next_expected_tag: u8,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            cursor: 0,
            next_expected_tag: 0x01,
        }
    }

    fn is_empty(&self) -> bool {
        self.cursor == self.buf.len()
    }

    fn read_u8(&mut self, label: &'static str) -> Result<u8, TranscriptError> {
        let byte = *self
            .buf
            .get(self.cursor)
            .ok_or(TranscriptError::Truncated(label))?;
        self.cursor += 1;
        Ok(byte)
    }

    fn read_u16(&mut self, label: &'static str) -> Result<u16, TranscriptError> {
        if self.cursor + 2 > self.buf.len() {
            return Err(TranscriptError::Truncated(label));
        }
        let value = u16::from_be_bytes(self.buf[self.cursor..self.cursor + 2].try_into().unwrap());
        self.cursor += 2;
        Ok(value)
    }

    fn read_u32(&mut self, label: &'static str) -> Result<u32, TranscriptError> {
        if self.cursor + 4 > self.buf.len() {
            return Err(TranscriptError::Truncated(label));
        }
        let value = u32::from_be_bytes(self.buf[self.cursor..self.cursor + 4].try_into().unwrap());
        self.cursor += 4;
        Ok(value)
    }

    fn read_slice(
        &mut self,
        length: usize,
        label: &'static str,
    ) -> Result<&'a [u8], TranscriptError> {
        if self
            .cursor
            .checked_add(length)
            .map_or(true, |end| end > self.buf.len())
        {
            return Err(TranscriptError::Truncated(label));
        }
        let slice = &self.buf[self.cursor..self.cursor + length];
        self.cursor += length;
        Ok(slice)
    }

    fn read_field(&mut self, expected_tag: u8) -> Result<&'a [u8], TranscriptError> {
        let tag = self.read_u8("transcript field tag")?;
        if tag != expected_tag {
            if tag < self.next_expected_tag {
                return Err(TranscriptError::DuplicateOrOutOfOrderField(tag));
            }
            return Err(TranscriptError::MissingField(expected_tag));
        }
        self.next_expected_tag = expected_tag.saturating_add(1);
        let length = self.read_u32("transcript field length")? as usize;
        self.read_slice(length, "transcript field value")
    }
}
