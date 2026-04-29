//! Mirror of the WASM-owned witness layout that the TypeScript side writes
//! through `copyWitnessToWasmMemory`.
//!
//! The wrapper allocates a 96-byte buffer in WASM linear memory and writes:
//! ```text
//! [  0 ..  64 )  kem_seed       (ML-KEM-768 seed; first 32 bytes are d, next 32 are z)
//! [ 64 ..  96 )  vault_root_key (32 bytes)
//! ```
//! For the vaultroot-only relation only `vault_root_key` is constrained, but
//! the layout still includes `kem_seed` so the same FFI works once the full
//! relation lands.

use core::ops::Range;
use zeroize::Zeroize;

pub const ML_KEM_SEED_BYTES: usize = 64;
pub const VAULT_ROOT_KEY_BYTES: usize = 32;
pub const HALO2_WITNESS_V1_BYTES: usize = ML_KEM_SEED_BYTES + VAULT_ROOT_KEY_BYTES;

pub const KEM_SEED_RANGE: Range<usize> = 0..ML_KEM_SEED_BYTES;
pub const VAULT_ROOT_KEY_RANGE: Range<usize> =
    ML_KEM_SEED_BYTES..ML_KEM_SEED_BYTES + VAULT_ROOT_KEY_BYTES;

/// A view over a raw witness buffer that does **not** copy out of the
/// pointer — callers are expected to keep the underlying memory live
/// (and to zeroize it on drop). Returned by [`view_witness_buffer`].
pub struct RawWitnessView<'a> {
    pub kem_seed: &'a [u8; ML_KEM_SEED_BYTES],
    pub vault_root_key: &'a [u8; VAULT_ROOT_KEY_BYTES],
}

#[derive(Debug)]
pub enum WitnessError {
    WrongLength,
}

impl core::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength => write!(
                f,
                "decryption proof witness buffer must be exactly {HALO2_WITNESS_V1_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for WitnessError {}

pub fn view_witness_buffer(buffer: &[u8]) -> Result<RawWitnessView<'_>, WitnessError> {
    if buffer.len() != HALO2_WITNESS_V1_BYTES {
        return Err(WitnessError::WrongLength);
    }
    let kem_seed: &[u8; ML_KEM_SEED_BYTES] = buffer[KEM_SEED_RANGE]
        .try_into()
        .expect("kem seed slice has the right length");
    let vault_root_key: &[u8; VAULT_ROOT_KEY_BYTES] = buffer[VAULT_ROOT_KEY_RANGE]
        .try_into()
        .expect("vault root key slice has the right length");
    Ok(RawWitnessView {
        kem_seed,
        vault_root_key,
    })
}

/// Owned witness used by the Rust prover. Drops zeroize the inner bytes.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct OwnedWitness {
    pub kem_seed: [u8; ML_KEM_SEED_BYTES],
    pub vault_root_key: [u8; VAULT_ROOT_KEY_BYTES],
}

impl OwnedWitness {
    pub fn from_buffer(buffer: &[u8]) -> Result<Self, WitnessError> {
        let view = view_witness_buffer(buffer)?;
        Ok(Self {
            kem_seed: *view.kem_seed,
            vault_root_key: *view.vault_root_key,
        })
    }

    pub fn write_buffer(&self, buffer: &mut [u8]) -> Result<(), WitnessError> {
        if buffer.len() != HALO2_WITNESS_V1_BYTES {
            return Err(WitnessError::WrongLength);
        }
        buffer[KEM_SEED_RANGE].copy_from_slice(&self.kem_seed);
        buffer[VAULT_ROOT_KEY_RANGE].copy_from_slice(&self.vault_root_key);
        Ok(())
    }
}
