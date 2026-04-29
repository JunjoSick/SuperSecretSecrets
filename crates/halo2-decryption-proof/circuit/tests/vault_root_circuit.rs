use halo2_axiom::dev::MockProver;
use halo2_axiom::halo2curves::ff::Field;
use halo2_decryption_proof_circuit::{
    circuit::{
        public_instances_for_vault_root_commitment, public_instances_to_commitment_bytes,
        VaultRootCommitmentCircuit, VAULT_ROOT_COMMITMENT_MIN_K,
    },
    commitment::bind_vault_root_plaintext_commitment,
    Bn254Scalar as Fr,
};

#[test]
fn vault_root_commitment_circuit_accepts_matching_witness() {
    let bundle_id = bytes8(11);
    let vault_root_key = bytes32(29);
    let circuit = VaultRootCommitmentCircuit::new(bundle_id, vault_root_key);
    let public_instances = circuit.public_instances_for_witness();

    let prover = MockProver::run(
        VAULT_ROOT_COMMITMENT_MIN_K,
        &circuit,
        vec![public_instances.to_vec()],
    )
    .expect("mock prover runs");
    prover.assert_satisfied();

    let expected_commitment =
        bind_vault_root_plaintext_commitment(&bundle_id, &vault_root_key).expect("typed inputs");
    assert_eq!(
        public_instances_to_commitment_bytes(&public_instances),
        expected_commitment,
    );
}

#[test]
fn vault_root_commitment_circuit_rejects_wrong_public_commitment() {
    let bundle_id = bytes8(17);
    let vault_root_key = bytes32(41);
    let circuit = VaultRootCommitmentCircuit::new(bundle_id, vault_root_key);
    let mut public_instances =
        public_instances_for_vault_root_commitment(&bundle_id, &vault_root_key);
    public_instances[1] += Fr::ONE;

    let prover = MockProver::run(
        VAULT_ROOT_COMMITMENT_MIN_K,
        &circuit,
        vec![public_instances.to_vec()],
    )
    .expect("mock prover runs");
    assert!(prover.verify().is_err());
}

#[test]
fn vault_root_commitment_circuit_rejects_wrong_public_bundle_id() {
    let bundle_id = bytes8(23);
    let vault_root_key = bytes32(53);
    let circuit = VaultRootCommitmentCircuit::new(bundle_id, vault_root_key);
    let mut public_instances =
        public_instances_for_vault_root_commitment(&bundle_id, &vault_root_key);
    public_instances[0] += Fr::ONE;

    let prover = MockProver::run(
        VAULT_ROOT_COMMITMENT_MIN_K,
        &circuit,
        vec![public_instances.to_vec()],
    )
    .expect("mock prover runs");
    assert!(prover.verify().is_err());
}

fn bytes8(seed: u8) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add(index as u8);
    }
    out
}

fn bytes32(seed: u8) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = seed.wrapping_add((index * 3) as u8);
    }
    out
}
