//! wasm-bindgen FFI for the SSS v3 Halo2 decryption proof backend.
//!
//! The exported functions are intentionally thin wrappers around the
//! host-testable functions in this crate. The TypeScript layer owns envelope
//! validation and transcript digest matching; this backend validates the
//! canonical public-input TLV, checks the vault-root witness commitment, and
//! runs Halo2/KZG proving or verification for the vaultroot-only relation.

#![deny(rust_2018_idioms)]
#![deny(unsafe_op_in_unsafe_fn)]

use std::io::{self, Cursor};

use halo2_axiom::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{create_proof, verify_proof, ProvingKey, VerifyingKey},
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::{ProverSHPLONK, VerifierSHPLONK},
        strategy::SingleStrategy,
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
    SerdeFormat,
};
use halo2_decryption_proof_circuit::{
    circuit::{
        public_instances_for_vault_root_commitment, public_instances_from_transcript,
        VaultRootCircuitInputError, VaultRootCommitmentCircuit,
    },
    transcript::{
        decode_public_inputs, transcript_digest, DecryptionProofPublicInputsV1, TranscriptError,
    },
    witness::{OwnedWitness, WitnessError, VAULT_ROOT_KEY_BYTES},
    Bn254Scalar,
};
use rand_core::OsRng;
use zeroize::Zeroizing;

const SERDE_FORMAT: SerdeFormat = SerdeFormat::Processed;

#[derive(Debug)]
pub enum BackendError {
    InvalidPublicInputs(String),
    InvalidWitness(String),
    InvalidSrs(String),
    InvalidProvingKey(String),
    InvalidVerifyingKey(String),
    InvalidCircuitInput(String),
    CommitmentMismatch,
    ProvingFailed(String),
}

impl core::fmt::Display for BackendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidPublicInputs(message) => write!(f, "invalid public inputs: {message}"),
            Self::InvalidWitness(message) => write!(f, "invalid witness: {message}"),
            Self::InvalidSrs(message) => write!(f, "invalid KZG SRS: {message}"),
            Self::InvalidProvingKey(message) => write!(f, "invalid Halo2 proving key: {message}"),
            Self::InvalidVerifyingKey(message) => {
                write!(f, "invalid Halo2 verifying key: {message}")
            }
            Self::InvalidCircuitInput(message) => write!(f, "invalid circuit input: {message}"),
            Self::CommitmentMismatch => {
                write!(f, "vault-root plaintext commitment does not match witness")
            }
            Self::ProvingFailed(message) => write!(f, "Halo2 proof generation failed: {message}"),
        }
    }
}

impl std::error::Error for BackendError {}

pub fn prove_decryption_proof_v1(
    encoded_public_inputs: &[u8],
    witness_bytes: &[u8],
    proving_key_bytes: &[u8],
    srs_bytes: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let witness = OwnedWitness::from_buffer(witness_bytes)?;
    prove_decryption_proof_v1_with_owned_witness(
        encoded_public_inputs,
        witness,
        proving_key_bytes,
        srs_bytes,
    )
}

fn prove_decryption_proof_v1_with_owned_witness(
    encoded_public_inputs: &[u8],
    witness: OwnedWitness,
    proving_key_bytes: &[u8],
    srs_bytes: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let vault_root_key = Zeroizing::new(witness.vault_root_key);
    prove_decryption_proof_v1_with_vault_root_key(
        encoded_public_inputs,
        &vault_root_key,
        proving_key_bytes,
        srs_bytes,
    )
}

fn prove_decryption_proof_v1_with_vault_root_key(
    encoded_public_inputs: &[u8],
    vault_root_key: &[u8; VAULT_ROOT_KEY_BYTES],
    proving_key_bytes: &[u8],
    srs_bytes: &[u8],
) -> Result<Vec<u8>, BackendError> {
    let public_inputs = decode_public_inputs(encoded_public_inputs)?;
    let digest = transcript_digest(encoded_public_inputs);
    let params = read_srs(srs_bytes)?;
    let pk = read_proving_key(proving_key_bytes)?;
    let instances = public_instances_from_transcript(&public_inputs, &digest)?;

    assert_witness_matches_public_commitment(&public_inputs, &digest, vault_root_key)?;

    let circuit =
        VaultRootCommitmentCircuit::new(*public_inputs.bundle_id, *vault_root_key, digest);
    let instance_columns: [&[Bn254Scalar]; 1] = [&instances[..]];
    let all_instances: [&[&[Bn254Scalar]]; 1] = [&instance_columns[..]];

    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(Vec::new());
    create_proof::<KZGCommitmentScheme<Bn256>, ProverSHPLONK<'_, Bn256>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &all_instances,
        OsRng,
        &mut transcript,
    )
    .map_err(|e| BackendError::ProvingFailed(e.to_string()))?;

    Ok(transcript.finalize())
}

pub fn verify_decryption_proof_v1(
    proof_bytes: &[u8],
    encoded_public_inputs: &[u8],
    verifying_key_bytes: &[u8],
    srs_bytes: &[u8],
) -> Result<bool, BackendError> {
    let public_inputs = decode_public_inputs(encoded_public_inputs)?;
    let digest = transcript_digest(encoded_public_inputs);
    let params = read_srs(srs_bytes)?;
    let vk = read_verifying_key(verifying_key_bytes)?;
    let instances = public_instances_from_transcript(&public_inputs, &digest)?;
    let instance_columns: [&[Bn254Scalar]; 1] = [&instances[..]];
    let all_instances: [&[&[Bn254Scalar]]; 1] = [&instance_columns[..]];

    let accepted = {
        let strategy = SingleStrategy::new(&params);
        let mut proof_reader = Cursor::new(proof_bytes);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&mut proof_reader);
        let result =
            verify_proof::<KZGCommitmentScheme<Bn256>, VerifierSHPLONK<'_, Bn256>, _, _, _>(
                &params,
                &vk,
                strategy,
                &all_instances,
                &mut transcript,
            )
            .is_ok();
        drop(transcript);
        result && proof_reader.position() == proof_bytes.len() as u64
    };

    Ok(accepted)
}

fn assert_witness_matches_public_commitment(
    public_inputs: &DecryptionProofPublicInputsV1<'_>,
    transcript_digest: &[u8; 32],
    vault_root_key: &[u8; VAULT_ROOT_KEY_BYTES],
) -> Result<(), BackendError> {
    let expected = public_instances_from_transcript(public_inputs, transcript_digest)?;
    let computed = public_instances_for_vault_root_commitment(
        public_inputs.bundle_id,
        vault_root_key,
        transcript_digest,
    );
    if computed == expected {
        Ok(())
    } else {
        Err(BackendError::CommitmentMismatch)
    }
}

fn read_srs(bytes: &[u8]) -> Result<ParamsKZG<Bn256>, BackendError> {
    let mut cursor = Cursor::new(bytes);
    let params = ParamsKZG::<Bn256>::read_custom(&mut cursor, SERDE_FORMAT)
        .map_err(|e| BackendError::InvalidSrs(e.to_string()))?;
    reject_trailing_bytes(&cursor, bytes.len(), "KZG SRS")
        .map_err(|e| BackendError::InvalidSrs(e.to_string()))?;
    Ok(params)
}

fn read_proving_key(bytes: &[u8]) -> Result<ProvingKey<G1Affine>, BackendError> {
    let mut cursor = Cursor::new(bytes);
    let pk = ProvingKey::<G1Affine>::read::<_, VaultRootCommitmentCircuit>(
        &mut cursor,
        SERDE_FORMAT,
        (),
    )
    .map_err(|e| BackendError::InvalidProvingKey(e.to_string()))?;
    reject_trailing_bytes(&cursor, bytes.len(), "Halo2 proving key")
        .map_err(|e| BackendError::InvalidProvingKey(e.to_string()))?;
    Ok(pk)
}

fn read_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<G1Affine>, BackendError> {
    let mut cursor = Cursor::new(bytes);
    let vk = VerifyingKey::<G1Affine>::read::<_, VaultRootCommitmentCircuit>(
        &mut cursor,
        SERDE_FORMAT,
        (),
    )
    .map_err(|e| BackendError::InvalidVerifyingKey(e.to_string()))?;
    reject_trailing_bytes(&cursor, bytes.len(), "Halo2 verifying key")
        .map_err(|e| BackendError::InvalidVerifyingKey(e.to_string()))?;
    Ok(vk)
}

fn reject_trailing_bytes(
    cursor: &Cursor<&[u8]>,
    len: usize,
    label: &'static str,
) -> io::Result<()> {
    if cursor.position() == len as u64 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("trailing bytes after {label}"),
        ))
    }
}

impl From<TranscriptError> for BackendError {
    fn from(error: TranscriptError) -> Self {
        Self::InvalidPublicInputs(error.to_string())
    }
}

impl From<WitnessError> for BackendError {
    fn from(error: WitnessError) -> Self {
        Self::InvalidWitness(error.to_string())
    }
}

impl From<VaultRootCircuitInputError> for BackendError {
    fn from(error: VaultRootCircuitInputError) -> Self {
        Self::InvalidCircuitInput(error.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
mod ffi {
    use super::{
        prove_decryption_proof_v1_with_vault_root_key,
        verify_decryption_proof_v1 as verify_decryption_proof_v1_core,
    };
    use halo2_decryption_proof_circuit::witness::{
        view_witness_buffer, HALO2_WITNESS_V1_BYTES, VAULT_ROOT_KEY_BYTES,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use wasm_bindgen::prelude::*;
    use zeroize::{Zeroize, Zeroizing};

    #[wasm_bindgen]
    pub fn allocate_buffer(len: usize) -> *mut u8 {
        let mut buf = vec![0u8; len];
        let ptr = buf.as_mut_ptr();
        core::mem::forget(buf);
        ptr
    }

    #[wasm_bindgen]
    pub fn free_buffer(ptr: *mut u8, len: usize) {
        if ptr.is_null() {
            return;
        }
        // SAFETY: this is the matched free for a `Vec<u8>` allocated by
        // `allocate_buffer`. The JS layer must pass the original len.
        let mut buf = unsafe { Vec::from_raw_parts(ptr, len, len) };
        buf.zeroize();
        drop(buf);
    }

    #[wasm_bindgen]
    pub fn allocate_witness_buffer(len: usize) -> *mut u8 {
        if len != HALO2_WITNESS_V1_BYTES {
            return core::ptr::null_mut();
        }
        allocate_buffer(len)
    }

    #[wasm_bindgen]
    pub fn free_witness_buffer(ptr: *mut u8, len: usize) {
        free_buffer(ptr, len);
    }

    #[wasm_bindgen]
    pub fn verify_decryption_proof_v1(
        proof_bytes: &[u8],
        encoded_public_inputs: &[u8],
        verifying_key_bytes: &[u8],
        srs_bytes: &[u8],
    ) -> Result<bool, JsError> {
        catch_unwind(AssertUnwindSafe(|| {
            verify_decryption_proof_v1_core(
                proof_bytes,
                encoded_public_inputs,
                verifying_key_bytes,
                srs_bytes,
            )
        }))
        .map_err(|_| JsError::new("Halo2 verifier backend panicked"))?
        .map_err(|e| JsError::new(&e.to_string()))
    }

    #[wasm_bindgen]
    pub fn prove_decryption_proof_v1_from_witness_ptr(
        encoded_public_inputs_ptr: *const u8,
        encoded_public_inputs_len: usize,
        witness_ptr: *const u8,
        witness_len: usize,
        proving_key_ptr: *const u8,
        proving_key_len: usize,
        srs_ptr: *const u8,
        srs_len: usize,
    ) -> Result<Box<[u8]>, JsError> {
        validate_ptr(
            encoded_public_inputs_ptr,
            encoded_public_inputs_len,
            "encoded public inputs",
        )?;
        validate_ptr(witness_ptr, witness_len, "witness")?;
        validate_ptr(proving_key_ptr, proving_key_len, "proving key")?;
        validate_ptr(srs_ptr, srs_len, "SRS")?;
        if witness_len != HALO2_WITNESS_V1_BYTES {
            return Err(JsError::new(
                "decryption proof witness buffer has the wrong length",
            ));
        }

        // SAFETY: pointers come from JS `wasm.memory`; the TS wrapper ensures
        // the ranges are valid and live for the duration of this call.
        let encoded_public_inputs = unsafe {
            core::slice::from_raw_parts(encoded_public_inputs_ptr, encoded_public_inputs_len)
        };
        let witness =
            unsafe { core::slice::from_raw_parts_mut(witness_ptr.cast_mut(), witness_len) };
        let proving_key = unsafe { core::slice::from_raw_parts(proving_key_ptr, proving_key_len) };
        let srs = unsafe { core::slice::from_raw_parts(srs_ptr, srs_len) };

        let mut vault_root_key = Zeroizing::new([0u8; VAULT_ROOT_KEY_BYTES]);
        match view_witness_buffer(witness) {
            Ok(view) => vault_root_key.copy_from_slice(view.vault_root_key),
            Err(e) => {
                witness.zeroize();
                return Err(JsError::new(&e.to_string()));
            }
        }
        witness.zeroize();

        catch_unwind(AssertUnwindSafe(|| {
            prove_decryption_proof_v1_with_vault_root_key(
                encoded_public_inputs,
                &vault_root_key,
                proving_key,
                srs,
            )
        }))
        .map_err(|_| {
            JsError::new(
                "Halo2 prover backend panicked after the JS-visible witness buffer was zeroized",
            )
        })?
        .map(Vec::into_boxed_slice)
        .map_err(|e| JsError::new(&e.to_string()))
    }

    fn validate_ptr<T>(ptr: *const T, len: usize, label: &'static str) -> Result<(), JsError> {
        if len > 0 && ptr.is_null() {
            return Err(JsError::new(&format!("{label} pointer is null")));
        }
        Ok(())
    }

    #[cfg(feature = "panic-hook")]
    #[wasm_bindgen(start)]
    pub fn install_panic_hook() {
        console_error_panic_hook::set_once();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_axiom::plonk::{keygen_pk, keygen_vk};
    use halo2_decryption_proof_circuit::{
        circuit::VAULT_ROOT_COMMITMENT_MIN_K,
        commitment::bind_vault_root_plaintext_commitment_typed,
        transcript::{
            AES_256_GCM_NONCE_BYTES, AES_256_GCM_TAG_BYTES, ML_KEM_768_CIPHERTEXT_BYTES,
            PAYLOAD_KIND_VAULT_ROOT, PROOF_AEAD_ID_AES_256_GCM,
            PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254, PROOF_KDF_ID_HKDF_SHA256,
            PROOF_KEM_ID_ML_KEM_768, TRANSCRIPT_DOMAIN, TRANSCRIPT_VERSION,
        },
        witness::{HALO2_WITNESS_V1_BYTES, ML_KEM_SEED_BYTES, VAULT_ROOT_KEY_BYTES},
    };
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn proves_and_verifies_vaultroot_only_artifact() {
        let (srs_bytes, proving_key_bytes, verifying_key_bytes) = generate_test_artifact();
        let bundle_id = [11u8; 8];
        let vault_root_key = [42u8; VAULT_ROOT_KEY_BYTES];
        let plaintext_commitment =
            bind_vault_root_plaintext_commitment_typed(&bundle_id, &vault_root_key);
        let public_inputs = encode_public_inputs(bundle_id, plaintext_commitment);
        let witness = encode_witness([7u8; ML_KEM_SEED_BYTES], vault_root_key);

        let proof =
            prove_decryption_proof_v1(&public_inputs, &witness, &proving_key_bytes, &srs_bytes)
                .expect("proof generation succeeds");
        assert!(!proof.is_empty());

        assert!(verify_decryption_proof_v1(
            &proof,
            &public_inputs,
            &verifying_key_bytes,
            &srs_bytes,
        )
        .expect("verification call succeeds"));

        let mut tampered_proof = proof.clone();
        let last = tampered_proof.len() - 1;
        tampered_proof[last] ^= 1;
        assert!(!verify_decryption_proof_v1(
            &tampered_proof,
            &public_inputs,
            &verifying_key_bytes,
            &srs_bytes,
        )
        .expect("verification call succeeds"));

        let mut tampered_public_inputs = public_inputs.clone();
        let last = tampered_public_inputs.len() - 1;
        tampered_public_inputs[last] ^= 1;
        assert!(!verify_decryption_proof_v1(
            &proof,
            &tampered_public_inputs,
            &verifying_key_bytes,
            &srs_bytes,
        )
        .expect("verification call succeeds"));
    }

    #[test]
    fn rejects_witness_that_does_not_match_public_commitment() {
        let (srs_bytes, proving_key_bytes, _) = generate_test_artifact();
        let bundle_id = [12u8; 8];
        let committed_key = [51u8; VAULT_ROOT_KEY_BYTES];
        let different_key = [52u8; VAULT_ROOT_KEY_BYTES];
        let plaintext_commitment =
            bind_vault_root_plaintext_commitment_typed(&bundle_id, &committed_key);
        let public_inputs = encode_public_inputs(bundle_id, plaintext_commitment);
        let witness = encode_witness([9u8; ML_KEM_SEED_BYTES], different_key);

        let err =
            prove_decryption_proof_v1(&public_inputs, &witness, &proving_key_bytes, &srs_bytes)
                .expect_err("mismatched commitment is rejected before proving");
        assert!(matches!(err, BackendError::CommitmentMismatch));
    }

    fn generate_test_artifact() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let mut rng = ChaCha20Rng::from_seed([3u8; 32]);
        let params = ParamsKZG::<Bn256>::setup(VAULT_ROOT_COMMITMENT_MIN_K, &mut rng);
        let circuit = VaultRootCommitmentCircuit::default();
        let vk = keygen_vk(&params, &circuit).expect("vk generation succeeds");
        let pk = keygen_pk(&params, vk, &circuit).expect("pk generation succeeds");

        let mut srs_bytes = Vec::new();
        params
            .write_custom(&mut srs_bytes, SERDE_FORMAT)
            .expect("SRS serializes");
        let proving_key_bytes = pk.to_bytes(SERDE_FORMAT);
        let verifying_key_bytes = pk.get_vk().to_bytes(SERDE_FORMAT);
        (srs_bytes, proving_key_bytes, verifying_key_bytes)
    }

    fn encode_witness(
        kem_seed: [u8; ML_KEM_SEED_BYTES],
        vault_root_key: [u8; VAULT_ROOT_KEY_BYTES],
    ) -> Vec<u8> {
        let mut out = vec![0u8; HALO2_WITNESS_V1_BYTES];
        out[..ML_KEM_SEED_BYTES].copy_from_slice(&kem_seed);
        out[ML_KEM_SEED_BYTES..].copy_from_slice(&vault_root_key);
        out
    }

    fn encode_public_inputs(bundle_id: [u8; 8], plaintext_commitment: [u8; 32]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(TRANSCRIPT_DOMAIN.len() as u16).to_be_bytes());
        out.extend_from_slice(TRANSCRIPT_DOMAIN.as_bytes());
        out.push(TRANSCRIPT_VERSION);
        encode_field(&mut out, 0x01, &bundle_id);
        encode_field(&mut out, 0x02, PAYLOAD_KIND_VAULT_ROOT.as_bytes());
        encode_field(
            &mut out,
            0x03,
            &[
                PROOF_KEM_ID_ML_KEM_768,
                PROOF_KDF_ID_HKDF_SHA256,
                PROOF_AEAD_ID_AES_256_GCM,
                PROOF_COMMITMENT_HASH_ID_POSEIDON2_BN254,
                0,
            ],
        );
        encode_field(&mut out, 0x04, &[0u8; 12]);
        encode_field(&mut out, 0x05, &[5u8; 32]);
        encode_field(&mut out, 0x06, &plaintext_commitment);
        encode_field(&mut out, 0x07, &[6u8; 32]);
        encode_field(&mut out, 0x08, &[7u8; ML_KEM_768_CIPHERTEXT_BYTES]);
        encode_field(&mut out, 0x09, &[8u8; AES_256_GCM_NONCE_BYTES]);
        encode_field(&mut out, 0x0a, &[9u8; AES_256_GCM_TAG_BYTES]);
        out
    }

    fn encode_field(out: &mut Vec<u8>, tag: u8, bytes: &[u8]) {
        out.push(tag);
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
    }
}
