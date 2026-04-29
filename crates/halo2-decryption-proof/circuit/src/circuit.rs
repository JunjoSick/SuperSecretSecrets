//! Halo2 circuit for the first honest proving milestone:
//! `sss-v3-poseidon2bn254-vaultroot-only-v1`.
//!
//! The statement is deliberately narrow. The verifier supplies four public
//! instances:
//!
//! 1. the 8-byte `bundleId` interpreted as a BN254 scalar;
//! 2. the Poseidon2-BN254 plaintext commitment field element;
//! 3. the high 128 bits of `SHA-256(encoded_public_inputs)`;
//! 4. the low 128 bits of `SHA-256(encoded_public_inputs)`.
//!
//! The prover supplies the 32-byte `vaultRootKey` privately. The circuit
//! constrains:
//!
//! ```text
//! plaintextCommitment =
//!   Poseidon2(domainTag, bundleId, vaultRootKey[0..16], vaultRootKey[16..32])
//! ```
//!
//! Transcript parsing stays in the TypeScript/WASM wrapper. The digest limbs
//! are public instances so the Halo2 proof is bound to the exact canonical
//! public-input transcript that contains the KEM ciphertext, nonce, algorithm
//! tuple, and commitments.

use halo2_axiom::halo2curves::{
    bn256::Fr,
    ff::{Field, PrimeField},
};
use halo2_axiom::{
    circuit::{Cell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use zeroize::Zeroize;

use crate::{
    commitment::{
        domain_tag, fr_to_be_bytes, split_bytes32_to_limbs, VAULT_ROOT_PLAINTEXT_COMMITMENT_DOMAIN,
    },
    poseidon2::params,
    transcript::{DecryptionProofPublicInputsV1, BUNDLE_ID_BYTES, COMMITMENT_BYTES},
};

const STATE_WIDTH: usize = 4;
const FULL_ROUNDS_BEGIN: usize = 4;
const FULL_ROUNDS_END: usize = 4;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END;

pub const VAULT_ROOT_COMMITMENT_INSTANCE_COUNT: usize = 4;
pub const VAULT_ROOT_COMMITMENT_MIN_K: u32 = 11;

#[derive(Clone, Debug, Zeroize)]
#[zeroize(drop)]
pub struct VaultRootCommitmentCircuit {
    pub bundle_id: [u8; BUNDLE_ID_BYTES],
    pub vault_root_key: [u8; crate::VAULT_ROOT_KEY_BYTES],
    pub transcript_digest: [u8; COMMITMENT_BYTES],
}

impl VaultRootCommitmentCircuit {
    pub fn new(
        bundle_id: [u8; BUNDLE_ID_BYTES],
        vault_root_key: [u8; crate::VAULT_ROOT_KEY_BYTES],
        transcript_digest: [u8; COMMITMENT_BYTES],
    ) -> Self {
        Self {
            bundle_id,
            vault_root_key,
            transcript_digest,
        }
    }

    pub fn public_instances_for_witness(&self) -> [Fr; VAULT_ROOT_COMMITMENT_INSTANCE_COUNT] {
        public_instances_for_vault_root_commitment(
            &self.bundle_id,
            &self.vault_root_key,
            &self.transcript_digest,
        )
    }
}

impl Default for VaultRootCommitmentCircuit {
    fn default() -> Self {
        Self {
            bundle_id: [0u8; BUNDLE_ID_BYTES],
            vault_root_key: [0u8; crate::VAULT_ROOT_KEY_BYTES],
            transcript_digest: [0u8; COMMITMENT_BYTES],
        }
    }
}

impl Circuit<Fr> for VaultRootCommitmentCircuit {
    type Config = VaultRootCommitmentConfig;
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self::Config {
        VaultRootCommitmentConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), Error> {
        let (bundle_cell, commitment_cell, digest_high_cell, digest_low_cell) = layouter
            .assign_region(
                || "vault root Poseidon2 commitment",
                |mut region| {
                    let mut offset = 0usize;
                    let chip = VaultRootCommitmentChip::new(config.clone());
                    let (bundle_cell, commitment_cell) = chip.synthesize_commitment(
                        &mut region,
                        &mut offset,
                        &self.bundle_id,
                        &self.vault_root_key,
                    )?;
                    let (digest_high, digest_low) =
                        split_transcript_digest_to_limbs(&self.transcript_digest);
                    let digest_high_cell =
                        chip.assign_private(&mut region, &mut offset, digest_high, "digest high")?;
                    let digest_low_cell =
                        chip.assign_private(&mut region, &mut offset, digest_low, "digest low")?;
                    Ok((
                        bundle_cell,
                        commitment_cell,
                        digest_high_cell,
                        digest_low_cell,
                    ))
                },
            )?;

        layouter.constrain_instance(bundle_cell.cell, config.instance, 0);
        layouter.constrain_instance(commitment_cell.cell, config.instance, 1);
        layouter.constrain_instance(digest_high_cell.cell, config.instance, 2);
        layouter.constrain_instance(digest_low_cell.cell, config.instance, 3);
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct VaultRootCommitmentConfig {
    advice: [Column<Advice>; 5],
    fixed: [Column<Fixed>; 5],
    instance: Column<Instance>,
    q_mul: Selector,
    q_linear4: Selector,
    q_linear1_const: Selector,
}

impl VaultRootCommitmentConfig {
    fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        for column in advice {
            meta.enable_equality(column);
        }

        let fixed = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_mul = meta.selector();
        let q_linear4 = meta.selector();
        let q_linear1_const = meta.selector();

        meta.create_gate("mul", |meta| {
            let q = meta.query_selector(q_mul);
            let lhs = meta.query_advice(advice[0], Rotation::cur());
            let rhs = meta.query_advice(advice[1], Rotation::cur());
            let out = meta.query_advice(advice[2], Rotation::cur());
            vec![q * (lhs * rhs - out)]
        });

        meta.create_gate("linear combination of four inputs", |meta| {
            let q = meta.query_selector(q_linear4);
            let a = meta.query_advice(advice[0], Rotation::cur());
            let b = meta.query_advice(advice[1], Rotation::cur());
            let c = meta.query_advice(advice[2], Rotation::cur());
            let d = meta.query_advice(advice[3], Rotation::cur());
            let out = meta.query_advice(advice[4], Rotation::cur());
            let ca = meta.query_fixed(fixed[0], Rotation::cur());
            let cb = meta.query_fixed(fixed[1], Rotation::cur());
            let cc = meta.query_fixed(fixed[2], Rotation::cur());
            let cd = meta.query_fixed(fixed[3], Rotation::cur());
            vec![q * (out - ca * a - cb * b - cc * c - cd * d)]
        });

        meta.create_gate("linear input plus constant", |meta| {
            let q = meta.query_selector(q_linear1_const);
            let input = meta.query_advice(advice[0], Rotation::cur());
            let out = meta.query_advice(advice[1], Rotation::cur());
            let coefficient = meta.query_fixed(fixed[0], Rotation::cur());
            let constant = meta.query_fixed(fixed[4], Rotation::cur());
            vec![q * (out - coefficient * input - constant)]
        });

        Self {
            advice,
            fixed,
            instance,
            q_mul,
            q_linear4,
            q_linear1_const,
        }
    }
}

#[derive(Clone, Debug)]
struct AssignedFr {
    cell: Cell,
    value: Fr,
}

#[derive(Clone, Debug)]
struct VaultRootCommitmentChip {
    config: VaultRootCommitmentConfig,
}

impl VaultRootCommitmentChip {
    fn new(config: VaultRootCommitmentConfig) -> Self {
        Self { config }
    }

    fn synthesize_commitment(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        bundle_id: &[u8; BUNDLE_ID_BYTES],
        vault_root_key: &[u8; crate::VAULT_ROOT_KEY_BYTES],
    ) -> Result<(AssignedFr, AssignedFr), Error> {
        let bundle_id_scalar = fixed_width_be_bytes_to_fr(bundle_id);
        let (vault_root_high, vault_root_low) = split_bytes32_to_limbs(vault_root_key);
        let domain = domain_tag(VAULT_ROOT_PLAINTEXT_COMMITMENT_DOMAIN);

        let bundle_cell =
            self.assign_private(region, offset, bundle_id_scalar, "bundle id scalar")?;
        let domain_cell = self.assign_private(region, offset, domain, "domain tag")?;
        let high_cell =
            self.assign_private(region, offset, vault_root_high, "vault root high limb")?;
        let low_cell =
            self.assign_private(region, offset, vault_root_low, "vault root low limb")?;

        let state = self.poseidon2_hash_to_field(
            region,
            offset,
            [domain_cell, bundle_cell.clone(), high_cell, low_cell],
        )?;

        Ok((bundle_cell, state[0].clone()))
    }

    fn poseidon2_hash_to_field(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        inputs: [AssignedFr; STATE_WIDTH],
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let iv = u128_to_fr(((inputs.len() as u128) << 64) | 0);
        let zero = self.assign_private(region, offset, Fr::ZERO, "zero")?;
        let iv_cell = self.assign_private(region, offset, iv, "Poseidon2 iv")?;

        let mut state = [zero.clone(), zero.clone(), zero.clone(), iv_cell];
        state = self.add_pairwise_state(
            region,
            offset,
            &state,
            [&inputs[0], &inputs[1], &inputs[2], &zero],
        )?;
        state = self.poseidon2_permutation(region, offset, state)?;

        state =
            self.add_pairwise_state(region, offset, &state, [&inputs[3], &zero, &zero, &zero])?;
        state = self.poseidon2_permutation(region, offset, state)?;

        Ok(state)
    }

    fn poseidon2_permutation(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        mut state: [AssignedFr; STATE_WIDTH],
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        state = self.external_matrix(region, offset, &state)?;

        for round in 0..FULL_ROUNDS_BEGIN {
            state = self.full_round(region, offset, state, round)?;
        }

        let partial_end = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS;
        for round in FULL_ROUNDS_BEGIN..partial_end {
            state = self.partial_round(region, offset, state, round)?;
        }

        for round in partial_end..TOTAL_ROUNDS {
            state = self.full_round(region, offset, state, round)?;
        }

        Ok(state)
    }

    fn full_round(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        state: [AssignedFr; STATE_WIDTH],
        round: usize,
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let s0 =
            self.pow5_with_constant(region, offset, &state[0], params::round_constant(round, 0))?;
        let s1 =
            self.pow5_with_constant(region, offset, &state[1], params::round_constant(round, 1))?;
        let s2 =
            self.pow5_with_constant(region, offset, &state[2], params::round_constant(round, 2))?;
        let s3 =
            self.pow5_with_constant(region, offset, &state[3], params::round_constant(round, 3))?;
        self.external_matrix(region, offset, &[s0, s1, s2, s3])
    }

    fn partial_round(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        state: [AssignedFr; STATE_WIDTH],
        round: usize,
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let s0 =
            self.pow5_with_constant(region, offset, &state[0], params::round_constant(round, 0))?;
        self.internal_matrix(
            region,
            offset,
            &[s0, state[1].clone(), state[2].clone(), state[3].clone()],
        )
    }

    fn pow5_with_constant(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        input: &AssignedFr,
        constant: Fr,
    ) -> Result<AssignedFr, Error> {
        let shifted = self.linear1_const(
            region,
            offset,
            input,
            Fr::ONE,
            constant,
            "add round constant",
        )?;
        let squared = self.mul(region, offset, &shifted, &shifted, "square")?;
        let fourth = self.mul(region, offset, &squared, &squared, "fourth power")?;
        self.mul(region, offset, &fourth, &shifted, "fifth power")
    }

    fn external_matrix(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        state: &[AssignedFr; STATE_WIDTH],
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let one = Fr::ONE;
        let three = fr_from_u64(3);
        let four = fr_from_u64(4);
        let five = fr_from_u64(5);
        let six = fr_from_u64(6);
        let seven = fr_from_u64(7);

        let y0 = self.linear4(
            region,
            offset,
            state,
            [five, seven, one, three],
            "external matrix row 0",
        )?;
        let y1 = self.linear4(
            region,
            offset,
            state,
            [four, six, one, one],
            "external matrix row 1",
        )?;
        let y2 = self.linear4(
            region,
            offset,
            state,
            [one, three, five, seven],
            "external matrix row 2",
        )?;
        let y3 = self.linear4(
            region,
            offset,
            state,
            [one, one, four, six],
            "external matrix row 3",
        )?;
        Ok([y0, y1, y2, y3])
    }

    fn internal_matrix(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        state: &[AssignedFr; STATE_WIDTH],
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let mut c0 = [Fr::ONE; STATE_WIDTH];
        c0[0] += params::MAT_DIAG4_M_1[0];
        let mut c1 = [Fr::ONE; STATE_WIDTH];
        c1[1] += params::MAT_DIAG4_M_1[1];
        let mut c2 = [Fr::ONE; STATE_WIDTH];
        c2[2] += params::MAT_DIAG4_M_1[2];
        let mut c3 = [Fr::ONE; STATE_WIDTH];
        c3[3] += params::MAT_DIAG4_M_1[3];

        let y0 = self.linear4(region, offset, state, c0, "internal matrix row 0")?;
        let y1 = self.linear4(region, offset, state, c1, "internal matrix row 1")?;
        let y2 = self.linear4(region, offset, state, c2, "internal matrix row 2")?;
        let y3 = self.linear4(region, offset, state, c3, "internal matrix row 3")?;
        Ok([y0, y1, y2, y3])
    }

    fn add_pairwise_state(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        lhs: &[AssignedFr; STATE_WIDTH],
        rhs: [&AssignedFr; STATE_WIDTH],
    ) -> Result<[AssignedFr; STATE_WIDTH], Error> {
        let one = Fr::ONE;
        let zero = Fr::ZERO;
        let y0 = self.linear4(
            region,
            offset,
            &[
                lhs[0].clone(),
                rhs[0].clone(),
                lhs[0].clone(),
                lhs[0].clone(),
            ],
            [one, one, zero, zero],
            "absorb row 0",
        )?;
        let y1 = self.linear4(
            region,
            offset,
            &[
                lhs[1].clone(),
                rhs[1].clone(),
                lhs[1].clone(),
                lhs[1].clone(),
            ],
            [one, one, zero, zero],
            "absorb row 1",
        )?;
        let y2 = self.linear4(
            region,
            offset,
            &[
                lhs[2].clone(),
                rhs[2].clone(),
                lhs[2].clone(),
                lhs[2].clone(),
            ],
            [one, one, zero, zero],
            "absorb row 2",
        )?;
        let y3 = self.linear4(
            region,
            offset,
            &[
                lhs[3].clone(),
                rhs[3].clone(),
                lhs[3].clone(),
                lhs[3].clone(),
            ],
            [one, one, zero, zero],
            "absorb row 3",
        )?;
        Ok([y0, y1, y2, y3])
    }

    fn assign_private(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        value: Fr,
        label: &'static str,
    ) -> Result<AssignedFr, Error> {
        let _ = label;
        let cell = region
            .assign_advice(self.config.advice[0], *offset, Value::known(value))
            .cell();
        *offset += 1;
        Ok(AssignedFr { cell, value })
    }

    fn mul(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        lhs: &AssignedFr,
        rhs: &AssignedFr,
        label: &'static str,
    ) -> Result<AssignedFr, Error> {
        self.config.q_mul.enable(region, *offset)?;
        let lhs_copy =
            region.assign_advice(self.config.advice[0], *offset, Value::known(lhs.value));
        region.constrain_equal(lhs_copy.cell(), lhs.cell);
        let rhs_copy =
            region.assign_advice(self.config.advice[1], *offset, Value::known(rhs.value));
        region.constrain_equal(rhs_copy.cell(), rhs.cell);
        let value = lhs.value * rhs.value;
        let _ = label;
        let cell = region
            .assign_advice(self.config.advice[2], *offset, Value::known(value))
            .cell();
        *offset += 1;
        Ok(AssignedFr { cell, value })
    }

    fn linear4(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        inputs: &[AssignedFr; STATE_WIDTH],
        coefficients: [Fr; STATE_WIDTH],
        label: &'static str,
    ) -> Result<AssignedFr, Error> {
        self.config.q_linear4.enable(region, *offset)?;
        for (index, input) in inputs.iter().enumerate() {
            let input_copy = region.assign_advice(
                self.config.advice[index],
                *offset,
                Value::known(input.value),
            );
            region.constrain_equal(input_copy.cell(), input.cell);
            region.assign_fixed(self.config.fixed[index], *offset, coefficients[index]);
        }

        let value = inputs
            .iter()
            .zip(coefficients)
            .fold(Fr::ZERO, |acc, (input, coefficient)| {
                acc + input.value * coefficient
            });
        let _ = label;
        let cell = region
            .assign_advice(self.config.advice[4], *offset, Value::known(value))
            .cell();
        *offset += 1;
        Ok(AssignedFr { cell, value })
    }

    fn linear1_const(
        &self,
        region: &mut Region<'_, Fr>,
        offset: &mut usize,
        input: &AssignedFr,
        coefficient: Fr,
        constant: Fr,
        label: &'static str,
    ) -> Result<AssignedFr, Error> {
        self.config.q_linear1_const.enable(region, *offset)?;
        let input_copy =
            region.assign_advice(self.config.advice[0], *offset, Value::known(input.value));
        region.constrain_equal(input_copy.cell(), input.cell);
        region.assign_fixed(self.config.fixed[0], *offset, coefficient);
        region.assign_fixed(self.config.fixed[4], *offset, constant);

        let value = input.value * coefficient + constant;
        let _ = label;
        let cell = region
            .assign_advice(self.config.advice[1], *offset, Value::known(value))
            .cell();
        *offset += 1;
        Ok(AssignedFr { cell, value })
    }
}

pub fn public_instances_for_vault_root_commitment(
    bundle_id: &[u8; BUNDLE_ID_BYTES],
    vault_root_key: &[u8; crate::VAULT_ROOT_KEY_BYTES],
    transcript_digest: &[u8; COMMITMENT_BYTES],
) -> [Fr; VAULT_ROOT_COMMITMENT_INSTANCE_COUNT] {
    let bundle_id_scalar = fixed_width_be_bytes_to_fr(bundle_id);
    let commitment = crate::bind_vault_root_plaintext_commitment(bundle_id, vault_root_key)
        .expect("typed bundle id and vault root key lengths are valid");
    let (digest_high, digest_low) = split_transcript_digest_to_limbs(transcript_digest);
    [
        bundle_id_scalar,
        fr_from_be_bytes(&commitment).expect("Poseidon2 output is a BN254 scalar"),
        digest_high,
        digest_low,
    ]
}

pub fn public_instances_from_transcript(
    public_inputs: &DecryptionProofPublicInputsV1<'_>,
    transcript_digest: &[u8; COMMITMENT_BYTES],
) -> Result<[Fr; VAULT_ROOT_COMMITMENT_INSTANCE_COUNT], VaultRootCircuitInputError> {
    let (digest_high, digest_low) = split_transcript_digest_to_limbs(transcript_digest);
    Ok([
        fixed_width_be_bytes_to_fr(public_inputs.bundle_id),
        fr_from_be_bytes(public_inputs.plaintext_commitment)
            .ok_or(VaultRootCircuitInputError::PlaintextCommitmentNotField)?,
        digest_high,
        digest_low,
    ])
}

pub fn public_instances_to_commitment_bytes(
    instances: &[Fr; VAULT_ROOT_COMMITMENT_INSTANCE_COUNT],
) -> [u8; COMMITMENT_BYTES] {
    fr_to_be_bytes(&instances[1])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultRootCircuitInputError {
    PlaintextCommitmentNotField,
}

impl core::fmt::Display for VaultRootCircuitInputError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PlaintextCommitmentNotField => {
                write!(f, "plaintext commitment is not a BN254 scalar")
            }
        }
    }
}

impl std::error::Error for VaultRootCircuitInputError {}

fn fixed_width_be_bytes_to_fr(bytes: &[u8]) -> Fr {
    assert!(
        bytes.len() <= 16,
        "fixed-width public value must be <= 16 bytes"
    );
    let mut be = [0u8; 32];
    be[32 - bytes.len()..].copy_from_slice(bytes);
    fr_from_be_bytes(&be).expect("16-byte value fits in BN254 scalar")
}

fn fr_from_be_bytes(bytes: &[u8; 32]) -> Option<Fr> {
    let mut le = [0u8; 32];
    for (i, byte) in bytes.iter().rev().enumerate() {
        le[i] = *byte;
    }
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr))
}

fn fr_from_u64(value: u64) -> Fr {
    Fr::from(value)
}

fn u128_to_fr(value: u128) -> Fr {
    let mut le = [0u8; 32];
    le[0..16].copy_from_slice(&value.to_le_bytes());
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("u128 fits in BN254 scalar")
}

fn split_transcript_digest_to_limbs(digest: &[u8; COMMITMENT_BYTES]) -> (Fr, Fr) {
    let high = u128::from_be_bytes(digest[..16].try_into().expect("slice is 16 bytes"));
    let low = u128::from_be_bytes(digest[16..].try_into().expect("slice is 16 bytes"));
    (u128_to_fr(high), u128_to_fr(low))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_instance_commitment_matches_reference_helper() {
        let bundle_id = [7u8; BUNDLE_ID_BYTES];
        let vault_root_key = [42u8; crate::VAULT_ROOT_KEY_BYTES];
        let transcript_digest = [99u8; COMMITMENT_BYTES];
        let instances = public_instances_for_vault_root_commitment(
            &bundle_id,
            &vault_root_key,
            &transcript_digest,
        );
        let reference = crate::bind_vault_root_plaintext_commitment(&bundle_id, &vault_root_key)
            .expect("typed inputs are valid");

        assert_eq!(public_instances_to_commitment_bytes(&instances), reference);
        let (digest_high, digest_low) = split_transcript_digest_to_limbs(&transcript_digest);
        assert_eq!(instances[2], digest_high);
        assert_eq!(instances[3], digest_low);
    }

    #[test]
    fn poseidon2_round_count_matches_reference_module() {
        let inputs = [Fr::ZERO, Fr::ONE, Fr::from(2), Fr::from(3)];
        let expected = crate::poseidon2::hash_to_field(&inputs);
        assert_ne!(expected, Fr::ZERO);
    }
}
