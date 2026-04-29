//! Out-of-circuit equivalent of
//! `bindPoseidon2Bn254VaultRootPlaintextCommitment` from
//! `src/crypto/commitments/proof-facing.ts`.
//!
//! Inputs:
//!   - `bundle_id`: 8 bytes (matches `POSEIDON2_BN254_BUNDLE_ID_BYTES`)
//!   - `vault_root_key`: 32 bytes split into two 16-byte big-endian limbs
//!
//! The TS layer prepends a domain tag derived from the SHA-256 of the
//! domain string truncated to its first 16 bytes (`poseidon2Bn254DomainTag`),
//! interpreted as a big-endian u128. We do the same here so the Rust output
//! matches `commitPoseidon2Bn254FieldElements({ domain, inputs })`.

use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::halo2curves::ff::PrimeField;
use sha2::{Digest, Sha256};

use crate::poseidon2;

pub const VAULT_ROOT_PLAINTEXT_COMMITMENT_DOMAIN: &str =
    "SSS/v3/poseidon2-bn254/plaintext-vault-root/v1";

pub const BUNDLE_ID_BYTES: usize = 8;
pub const VAULT_ROOT_KEY_BYTES: usize = 32;
pub const COMMITMENT_BYTES: usize = 32;
pub const LIMB_BYTES: usize = 16;

#[derive(Debug)]
pub enum CommitmentError {
    InvalidBundleIdLength,
    InvalidVaultRootKeyLength,
}

impl core::fmt::Display for CommitmentError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidBundleIdLength => {
                write!(
                    f,
                    "Poseidon2-BN254 bundleId must be exactly {BUNDLE_ID_BYTES} bytes"
                )
            }
            Self::InvalidVaultRootKeyLength => {
                write!(
                    f,
                    "Poseidon2-BN254 vault root key must be exactly {VAULT_ROOT_KEY_BYTES} bytes"
                )
            }
        }
    }
}

impl std::error::Error for CommitmentError {}

pub fn bind_vault_root_plaintext_commitment(
    bundle_id: &[u8],
    vault_root_key: &[u8],
) -> Result<[u8; COMMITMENT_BYTES], CommitmentError> {
    if bundle_id.len() != BUNDLE_ID_BYTES {
        return Err(CommitmentError::InvalidBundleIdLength);
    }
    if vault_root_key.len() != VAULT_ROOT_KEY_BYTES {
        return Err(CommitmentError::InvalidVaultRootKeyLength);
    }
    let bundle_id_array: &[u8; BUNDLE_ID_BYTES] = bundle_id.try_into().expect("checked above");
    let vault_root_array: &[u8; VAULT_ROOT_KEY_BYTES] =
        vault_root_key.try_into().expect("checked above");
    Ok(bind_vault_root_plaintext_commitment_typed(
        bundle_id_array,
        vault_root_array,
    ))
}

pub fn bind_vault_root_plaintext_commitment_typed(
    bundle_id: &[u8; BUNDLE_ID_BYTES],
    vault_root_key: &[u8; VAULT_ROOT_KEY_BYTES],
) -> [u8; COMMITMENT_BYTES] {
    let domain_tag = domain_tag(VAULT_ROOT_PLAINTEXT_COMMITMENT_DOMAIN);
    let bundle_id_scalar = right_padded_be_bytes_to_fr(bundle_id);
    let (vault_root_high, vault_root_low) = split_bytes32_to_limbs(vault_root_key);

    let inputs = [
        domain_tag,
        bundle_id_scalar,
        vault_root_high,
        vault_root_low,
    ];
    let output = poseidon2::hash_to_field(&inputs);
    fr_to_be_bytes(&output)
}

/// `poseidon2Bn254DomainTag(domain)` from the TS package: take the first 16
/// bytes of `sha256(domain)` and interpret them as a big-endian u128.
pub fn domain_tag(domain: &str) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let digest = hasher.finalize();
    let mut be = [0u8; 16];
    be.copy_from_slice(&digest[..16]);
    let mut le = [0u8; 32];
    for (i, byte) in be.iter().rev().enumerate() {
        le[i] = *byte;
    }
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("domain tag fits in BN254 scalar")
}

/// `splitBytes32ToBn254Limbs128(bytes)` — 32 bytes split into two big-endian
/// 16-byte limbs.
pub fn split_bytes32_to_limbs(bytes: &[u8; VAULT_ROOT_KEY_BYTES]) -> (Fr, Fr) {
    let high = right_padded_be_bytes_to_fr_slice(&bytes[..LIMB_BYTES]);
    let low = right_padded_be_bytes_to_fr_slice(&bytes[LIMB_BYTES..]);
    (high, low)
}

/// Pad an N-byte big-endian value into a 32-byte BN254 scalar, matching
/// `fixedWidthBytesToBn254Scalar`.
fn right_padded_be_bytes_to_fr<const N: usize>(bytes: &[u8; N]) -> Fr {
    right_padded_be_bytes_to_fr_slice(bytes)
}

fn right_padded_be_bytes_to_fr_slice(bytes: &[u8]) -> Fr {
    assert!(bytes.len() <= 32, "input must fit in BN254 scalar");
    let mut be = [0u8; 32];
    be[32 - bytes.len()..].copy_from_slice(bytes);
    let mut le = [0u8; 32];
    for (i, byte) in be.iter().rev().enumerate() {
        le[i] = *byte;
    }
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("right-padded bytes fit in BN254 scalar")
}

pub fn fr_to_be_bytes(value: &Fr) -> [u8; COMMITMENT_BYTES] {
    let repr = value.to_repr();
    let le = repr.as_ref();
    let mut be = [0u8; COMMITMENT_BYTES];
    for (i, byte) in le.iter().rev().enumerate() {
        be[i] = *byte;
    }
    be
}

pub fn parse_hex_fr(hex_str: &str) -> Option<Fr> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != COMMITMENT_BYTES {
        return None;
    }
    let mut le = [0u8; COMMITMENT_BYTES];
    for (i, byte) in bytes.iter().rev().enumerate() {
        le[i] = *byte;
    }
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr))
}
