//! Artifact generator for the SSS v3 vaultroot-only Halo2 backend.
//!
//! It emits the KZG SRS, proving key, verifying key, trusted-setup
//! identifier, and a JSON sidecar whose metadata hashes match the
//! TypeScript artifact codec.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
};

use halo2_axiom::{
    halo2curves::bn256::{Bn256, G1Affine},
    plonk::{keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::{commitment::Params, kzg::commitment::ParamsKZG},
    SerdeFormat,
};
use halo2_decryption_proof_circuit::{
    circuit::{VaultRootCommitmentCircuit, VAULT_ROOT_COMMITMENT_MIN_K},
    relation::{relation_v1_vaultroot_only_digest, RELATION_V1_VAULTROOT_ONLY_ID},
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

const DEFAULT_OUTPUT_DIR: &str = "target/halo2-vaultroot-only-artifact";
const ARTIFACT_SCHEMA: &str = "sss-v3-halo2-artifact-v1";
const VERIFIER_ARTIFACT_DIGEST_DOMAIN: &str = "SSS/v3/decryption-proof/verifier-artifact/v1";

const SCHEME_ID_HALO2_KZG: u8 = 0x01;
const PCS_ID_KZG: u8 = 0x01;
const CURVE_ID_BN254: u8 = 0x01;
const CIRCUIT_VERSION_MAJOR: u8 = 0;
const CIRCUIT_VERSION_MINOR: u8 = 1;
const CIRCUIT_VERSION_PATCH: u8 = 0;

const SRS_FILE: &str = "srs.bin";
const PROVING_KEY_FILE: &str = "pk.bin";
const VERIFYING_KEY_FILE: &str = "vk.bin";
const TRUSTED_SETUP_ID_FILE: &str = "trusted-setup-id.txt";
const WASM_BUILD_FILE: &str = "wasm-build.wasm";
const MANIFEST_FILE: &str = "artifact-manifest.json";

const SERDE_FORMAT: SerdeFormat = SerdeFormat::Processed;
const SERDE_FORMAT_NAME: &str = "processed";
const SRS_SOURCE_DETERMINISTIC_DEV: &str = "deterministic-dev";
const SRS_SOURCE_EXTERNAL: &str = "external";

fn main() -> Result<(), Box<dyn Error>> {
    let config = match Config::parse(env::args().skip(1)) {
        Ok(config) => config,
        Err(ParseOutcome::Help) => {
            print_usage();
            return Ok(());
        }
        Err(ParseOutcome::Error(message)) => return Err(message.into()),
    };

    let generated = generate_artifact(&config)?;
    write_artifact(&config.output_dir, &generated)?;

    println!("artifact_dir = {}", config.output_dir.display());
    println!("relation_id = {RELATION_V1_VAULTROOT_ONLY_ID}");
    println!(
        "relation_digest = {}",
        hex::encode(generated.relation_digest)
    );
    println!(
        "verifier_artifact_digest = {}",
        hex::encode(generated.verifier_artifact_digest)
    );
    println!("srs = {SRS_FILE} ({} bytes)", generated.srs_bytes.len());
    println!(
        "pk = {PROVING_KEY_FILE} ({} bytes)",
        generated.proving_key_bytes.len()
    );
    println!(
        "vk = {VERIFYING_KEY_FILE} ({} bytes)",
        generated.verifying_key_bytes.len()
    );
    println!("manifest = {MANIFEST_FILE}");

    if config.srs_input.is_none() {
        eprintln!(
            "warning: generated a deterministic development KZG SRS. Replace it with ceremony-backed parameters before production use."
        );
    }
    if config.wasm_input.is_none() {
        eprintln!("warning: no wasm build was supplied; manifest wasmBuildHash is sha256(empty).");
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    output_dir: PathBuf,
    k: u32,
    srs_input: Option<PathBuf>,
    wasm_input: Option<PathBuf>,
    allow_dev_srs: bool,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, ParseOutcome> {
        let mut output_dir = PathBuf::from(DEFAULT_OUTPUT_DIR);
        let mut k = VAULT_ROOT_COMMITMENT_MIN_K;
        let mut srs_input = None;
        let mut wasm_input = None;
        let mut allow_dev_srs = false;

        let args = args.into_iter().collect::<Vec<_>>();
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--help" | "-h" => return Err(ParseOutcome::Help),
                "--out" => {
                    index += 1;
                    output_dir = PathBuf::from(
                        args.get(index)
                            .ok_or_else(|| ParseOutcome::Error("--out requires a path".into()))?,
                    );
                }
                "--k" => {
                    index += 1;
                    let raw = args
                        .get(index)
                        .ok_or_else(|| ParseOutcome::Error("--k requires an integer".into()))?;
                    k = raw
                        .parse::<u32>()
                        .map_err(|_| ParseOutcome::Error("--k must be an integer".into()))?;
                    if k < VAULT_ROOT_COMMITMENT_MIN_K {
                        return Err(ParseOutcome::Error(format!(
                            "--k must be at least {VAULT_ROOT_COMMITMENT_MIN_K}"
                        )));
                    }
                }
                "--srs-in" => {
                    index += 1;
                    srs_input =
                        Some(PathBuf::from(args.get(index).ok_or_else(|| {
                            ParseOutcome::Error("--srs-in requires a path".into())
                        })?));
                }
                "--wasm" => {
                    index += 1;
                    wasm_input =
                        Some(PathBuf::from(args.get(index).ok_or_else(|| {
                            ParseOutcome::Error("--wasm requires a path".into())
                        })?));
                }
                "--allow-dev-srs" => {
                    allow_dev_srs = true;
                }
                unknown => {
                    return Err(ParseOutcome::Error(format!("unknown argument: {unknown}")));
                }
            }
            index += 1;
        }

        Ok(Self {
            output_dir,
            k,
            srs_input,
            wasm_input,
            allow_dev_srs,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParseOutcome {
    Help,
    Error(String),
}

fn print_usage() {
    println!(
        "usage: cargo run -p halo2-decryption-proof-keygen -- [--out DIR] [--k K] [--srs-in FILE | --allow-dev-srs] [--wasm FILE]\n\n\
         Defaults:\n  --out {DEFAULT_OUTPUT_DIR}\n  --k {VAULT_ROOT_COMMITMENT_MIN_K}\n\n\
         --allow-dev-srs is required to emit a deterministic local-development SRS."
    );
}

#[derive(Debug)]
struct GeneratedArtifact {
    relation_digest: [u8; 32],
    verifier_artifact_digest: [u8; 32],
    manifest: ArtifactManifest,
    srs_bytes: Vec<u8>,
    proving_key_bytes: Vec<u8>,
    verifying_key_bytes: Vec<u8>,
    trusted_setup_id_bytes: Vec<u8>,
    wasm_build_bytes: Option<Vec<u8>>,
}

fn generate_artifact(config: &Config) -> Result<GeneratedArtifact, Box<dyn Error>> {
    let (params, mut srs_bytes, srs_source) = load_or_generate_srs(config)?;
    let circuit = VaultRootCommitmentCircuit::default();
    let vk: VerifyingKey<G1Affine> = keygen_vk(&params, &circuit)?;
    let pk: ProvingKey<G1Affine> = keygen_pk(&params, vk, &circuit)?;

    let verifying_key_bytes = pk.get_vk().to_bytes(SERDE_FORMAT);
    let proving_key_bytes = pk.to_bytes(SERDE_FORMAT);
    if srs_bytes.is_empty() {
        params.write_custom(&mut srs_bytes, SERDE_FORMAT)?;
    }

    let wasm_build_bytes = match &config.wasm_input {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    let wasm_hash = sha256_bytes(wasm_build_bytes.as_deref().unwrap_or(&[]));
    let verifying_key_hash = sha256_bytes(&verifying_key_bytes);
    let proving_key_hash = sha256_bytes(&proving_key_bytes);
    let srs_hash = sha256_bytes(&srs_bytes);
    let trusted_setup_id_bytes = trusted_setup_id_bytes(config.k, &srs_source, &srs_hash);
    let trusted_setup_id_digest = sha256_bytes(&trusted_setup_id_bytes);
    let relation_digest = relation_v1_vaultroot_only_digest();

    let metadata = ArtifactMetadataBytes {
        scheme_id: SCHEME_ID_HALO2_KZG,
        pcs_id: PCS_ID_KZG,
        curve_id: CURVE_ID_BN254,
        circuit_version_major: CIRCUIT_VERSION_MAJOR,
        circuit_version_minor: CIRCUIT_VERSION_MINOR,
        circuit_version_patch: CIRCUIT_VERSION_PATCH,
        relation_digest,
        trusted_setup_id_digest,
        wasm_build_hash: wasm_hash,
        verifying_key_hash,
    };
    let verifier_artifact_digest = digest_artifact_metadata(&metadata);

    let manifest = ArtifactManifest {
        schema: ARTIFACT_SCHEMA,
        relation_id: RELATION_V1_VAULTROOT_ONLY_ID,
        relation_digest: hex::encode(relation_digest),
        verifier_artifact_digest: hex::encode(verifier_artifact_digest),
        proving_key_hash: hex::encode(proving_key_hash),
        srs_hash: hex::encode(srs_hash),
        srs_source: srs_source.as_str(),
        serde_format: SERDE_FORMAT_NAME,
        metadata: JsonArtifactMetadata {
            scheme_id: SCHEME_ID_HALO2_KZG,
            relation_digest: hex::encode(relation_digest),
            pcs_id: PCS_ID_KZG,
            curve_id: CURVE_ID_BN254,
            trusted_setup_id_digest: hex::encode(trusted_setup_id_digest),
            circuit_version_major: CIRCUIT_VERSION_MAJOR,
            circuit_version_minor: CIRCUIT_VERSION_MINOR,
            circuit_version_patch: CIRCUIT_VERSION_PATCH,
            wasm_build_hash: hex::encode(wasm_hash),
            verifying_key_hash: hex::encode(verifying_key_hash),
        },
        circuit: JsonCircuit {
            name: "VaultRootCommitmentCircuit",
            k: config.k,
            public_instances: vec![
                "bundleId".into(),
                "plaintextCommitment".into(),
                "transcriptDigestHigh128".into(),
                "transcriptDigestLow128".into(),
            ],
            version: format!(
                "{CIRCUIT_VERSION_MAJOR}.{CIRCUIT_VERSION_MINOR}.{CIRCUIT_VERSION_PATCH}"
            ),
        },
        files: JsonArtifactFiles {
            srs: SRS_FILE,
            proving_key: PROVING_KEY_FILE,
            verifying_key: VERIFYING_KEY_FILE,
            trusted_setup_id: TRUSTED_SETUP_ID_FILE,
            wasm_build: wasm_build_bytes.as_ref().map(|_| WASM_BUILD_FILE),
        },
        warnings: artifact_warnings(config),
    };

    Ok(GeneratedArtifact {
        relation_digest,
        verifier_artifact_digest,
        manifest,
        srs_bytes,
        proving_key_bytes,
        verifying_key_bytes,
        trusted_setup_id_bytes,
        wasm_build_bytes,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SrsSource {
    DeterministicDev,
    External,
}

impl SrsSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::DeterministicDev => SRS_SOURCE_DETERMINISTIC_DEV,
            Self::External => SRS_SOURCE_EXTERNAL,
        }
    }
}

fn load_or_generate_srs(
    config: &Config,
) -> Result<(ParamsKZG<Bn256>, Vec<u8>, SrsSource), Box<dyn Error>> {
    if let Some(path) = &config.srs_input {
        let bytes = fs::read(path)?;
        let params = ParamsKZG::<Bn256>::read_custom(&mut &bytes[..], SERDE_FORMAT)?;
        if params.k() != config.k {
            return Err(format!(
                "SRS k mismatch: --k is {}, but {} contains k={}",
                config.k,
                path.display(),
                params.k()
            )
            .into());
        }
        return Ok((params, bytes, SrsSource::External));
    }

    if !config.allow_dev_srs {
        return Err(
            "refusing to generate deterministic development SRS without --allow-dev-srs or --srs-in"
                .into(),
        );
    }

    let mut rng = ChaCha20Rng::from_seed(dev_srs_seed(config.k));
    let params = ParamsKZG::<Bn256>::setup(config.k, &mut rng);
    let mut bytes = Vec::new();
    params.write_custom(&mut bytes, SERDE_FORMAT)?;
    Ok((params, bytes, SrsSource::DeterministicDev))
}

fn write_artifact(output_dir: &Path, artifact: &GeneratedArtifact) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(output_dir)?;
    fs::write(output_dir.join(SRS_FILE), &artifact.srs_bytes)?;
    fs::write(
        output_dir.join(PROVING_KEY_FILE),
        &artifact.proving_key_bytes,
    )?;
    fs::write(
        output_dir.join(VERIFYING_KEY_FILE),
        &artifact.verifying_key_bytes,
    )?;
    fs::write(
        output_dir.join(TRUSTED_SETUP_ID_FILE),
        &artifact.trusted_setup_id_bytes,
    )?;
    if let Some(wasm_build_bytes) = &artifact.wasm_build_bytes {
        fs::write(output_dir.join(WASM_BUILD_FILE), wasm_build_bytes)?;
    }
    let manifest = serde_json::to_vec_pretty(&artifact.manifest)?;
    fs::write(output_dir.join(MANIFEST_FILE), manifest)?;
    Ok(())
}

fn dev_srs_seed(k: u32) -> [u8; 32] {
    sha256_bytes(format!("SSS/v3/halo2-kzg-bn254/dev-srs/v1;k={k}").as_bytes())
}

fn trusted_setup_id_bytes(k: u32, source: &SrsSource, srs_hash: &[u8; 32]) -> Vec<u8> {
    let source_label = match source {
        SrsSource::DeterministicDev => SRS_SOURCE_DETERMINISTIC_DEV,
        SrsSource::External => SRS_SOURCE_EXTERNAL,
    };
    format!(
        "sss-v3-halo2-kzg-bn254-srs-v1\nsource={source_label}\nk={k}\nsrsSha256={}\nserde={SERDE_FORMAT_NAME}\n",
        hex::encode(srs_hash)
    )
    .into_bytes()
}

#[derive(Clone, Copy)]
struct ArtifactMetadataBytes {
    scheme_id: u8,
    relation_digest: [u8; 32],
    pcs_id: u8,
    curve_id: u8,
    trusted_setup_id_digest: [u8; 32],
    circuit_version_major: u8,
    circuit_version_minor: u8,
    circuit_version_patch: u8,
    wasm_build_hash: [u8; 32],
    verifying_key_hash: [u8; 32],
}

fn digest_artifact_metadata(metadata: &ArtifactMetadataBytes) -> [u8; 32] {
    sha256_bytes(&encode_artifact_metadata(metadata))
}

fn encode_artifact_metadata(metadata: &ArtifactMetadataBytes) -> Vec<u8> {
    let domain = VERIFIER_ARTIFACT_DIGEST_DOMAIN.as_bytes();
    let mut out = Vec::with_capacity(2 + domain.len() + 6 + 32 * 4);
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&[
        metadata.scheme_id,
        metadata.pcs_id,
        metadata.curve_id,
        metadata.circuit_version_major,
        metadata.circuit_version_minor,
        metadata.circuit_version_patch,
    ]);
    out.extend_from_slice(&metadata.relation_digest);
    out.extend_from_slice(&metadata.trusted_setup_id_digest);
    out.extend_from_slice(&metadata.wasm_build_hash);
    out.extend_from_slice(&metadata.verifying_key_hash);
    out
}

fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn artifact_warnings(config: &Config) -> Vec<String> {
    let mut warnings = Vec::new();
    if config.srs_input.is_none() {
        warnings.push(
            "deterministic development SRS; replace with ceremony-backed BN254/KZG parameters before production"
                .into(),
        );
    }
    if config.wasm_input.is_none() {
        warnings.push("no WASM build supplied; wasmBuildHash is sha256(empty)".into());
    }
    warnings
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct ArtifactManifest {
    schema: &'static str,
    relation_id: &'static str,
    relation_digest: String,
    verifier_artifact_digest: String,
    proving_key_hash: String,
    srs_hash: String,
    srs_source: &'static str,
    serde_format: &'static str,
    metadata: JsonArtifactMetadata,
    circuit: JsonCircuit,
    files: JsonArtifactFiles,
    warnings: Vec<String>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct JsonArtifactMetadata {
    scheme_id: u8,
    relation_digest: String,
    pcs_id: u8,
    curve_id: u8,
    trusted_setup_id_digest: String,
    circuit_version_major: u8,
    circuit_version_minor: u8,
    circuit_version_patch: u8,
    wasm_build_hash: String,
    verifying_key_hash: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct JsonCircuit {
    name: &'static str,
    k: u32,
    public_instances: Vec<String>,
    version: String,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
struct JsonArtifactFiles {
    srs: &'static str,
    proving_key: &'static str,
    verifying_key: &'static str,
    trusted_setup_id: &'static str,
    wasm_build: Option<&'static str>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_config() {
        let config = Config::parse(Vec::<String>::new()).expect("defaults parse");
        assert_eq!(config.output_dir, PathBuf::from(DEFAULT_OUTPUT_DIR));
        assert_eq!(config.k, VAULT_ROOT_COMMITMENT_MIN_K);
        assert_eq!(config.srs_input, None);
        assert_eq!(config.wasm_input, None);
        assert!(!config.allow_dev_srs);
    }

    #[test]
    fn parses_explicit_dev_srs_gate() {
        let config = Config::parse(vec!["--allow-dev-srs".into()]).expect("config parses");
        assert!(config.allow_dev_srs);
    }

    #[test]
    fn artifact_metadata_encoding_matches_ts_field_order() {
        let metadata = ArtifactMetadataBytes {
            scheme_id: 1,
            pcs_id: 1,
            curve_id: 1,
            circuit_version_major: 0,
            circuit_version_minor: 1,
            circuit_version_patch: 0,
            relation_digest: [2u8; 32],
            trusted_setup_id_digest: [3u8; 32],
            wasm_build_hash: [4u8; 32],
            verifying_key_hash: [5u8; 32],
        };
        let encoded = encode_artifact_metadata(&metadata);
        let domain = VERIFIER_ARTIFACT_DIGEST_DOMAIN.as_bytes();
        assert_eq!(&encoded[0..2], &(domain.len() as u16).to_be_bytes());
        assert_eq!(&encoded[2..2 + domain.len()], domain);
        assert_eq!(
            &encoded[2 + domain.len()..8 + domain.len()],
            &[1, 1, 1, 0, 1, 0]
        );
        assert_eq!(&encoded[8 + domain.len()..40 + domain.len()], &[2u8; 32]);
        assert_eq!(digest_artifact_metadata(&metadata).len(), 32);
    }
}
