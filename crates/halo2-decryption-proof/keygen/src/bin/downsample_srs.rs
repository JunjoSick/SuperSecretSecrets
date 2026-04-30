use std::{
    env,
    error::Error,
    fs::File,
    io::{BufReader, BufWriter, Read},
    path::{Path, PathBuf},
};

use halo2_axiom::{
    halo2curves::bn256::Bn256, poly::commitment::Params, poly::kzg::commitment::ParamsKZG,
    SerdeFormat,
};
use halo2_decryption_proof_circuit::artifacts::EXPECTED_K;
use sha2::{Digest, Sha256};

const SRS_SERDE_FORMAT: SerdeFormat = SerdeFormat::RawBytes;

fn main() -> Result<(), Box<dyn Error>> {
    let config = Config::parse(env::args().skip(1))?;

    let source_digest = sha256_file(&config.source_path)?;
    if source_digest != config.expected_source_sha256 {
        return Err(format!(
            "source SRS digest mismatch: expected {}, got {}",
            hex::encode(config.expected_source_sha256),
            hex::encode(source_digest)
        )
        .into());
    }

    let mut reader = BufReader::new(File::open(&config.source_path)?);
    let mut params = ParamsKZG::<Bn256>::read_custom(&mut reader, SRS_SERDE_FORMAT)
        .map_err(|e| format!("failed to read source SRS as ParamsKZG<Bn256>: {e}"))?;
    if params.k() < config.expected_k {
        return Err(format!(
            "source SRS k={} is smaller than expected k={}",
            params.k(),
            config.expected_k
        )
        .into());
    }

    params.downsize(config.expected_k);
    if params.k() != config.expected_k {
        return Err(format!(
            "downsampled SRS has wrong k: expected {}, got {}",
            config.expected_k,
            params.k()
        )
        .into());
    }

    let mut writer = BufWriter::new(File::create(&config.output_path)?);
    params.write_custom(&mut writer, SRS_SERDE_FORMAT)?;
    drop(writer);

    let output_digest = sha256_file(&config.output_path)?;
    println!("wrote {}", config.output_path.display());
    println!("downsampled_srs_sha256={}", hex::encode(output_digest));

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    source_path: PathBuf,
    output_path: PathBuf,
    expected_source_sha256: [u8; 32],
    expected_k: u32,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, Box<dyn Error>> {
        let args = args.into_iter().collect::<Vec<_>>();
        if args.iter().any(|arg| arg == "--help" || arg == "-h") {
            print_usage();
            std::process::exit(0);
        }

        let mut source_path = None;
        let mut output_path = None;
        let mut expected_source_sha256 = None;
        let mut expected_k = EXPECTED_K;
        let mut index = 0usize;
        while index < args.len() {
            match args[index].as_str() {
                "--source" => {
                    index += 1;
                    source_path = Some(PathBuf::from(required_arg(&args, index, "--source")?));
                }
                "--out" => {
                    index += 1;
                    output_path = Some(PathBuf::from(required_arg(&args, index, "--out")?));
                }
                "--expected-source-sha256" => {
                    index += 1;
                    expected_source_sha256 = Some(parse_sha256_hex(required_arg(
                        &args,
                        index,
                        "--expected-source-sha256",
                    )?)?);
                }
                "--k" => {
                    index += 1;
                    expected_k = required_arg(&args, index, "--k")?.parse::<u32>()?;
                }
                unknown => return Err(format!("unknown argument: {unknown}").into()),
            }
            index += 1;
        }

        let source_path = source_path.ok_or("--source is required")?;
        let output_path = output_path.ok_or("--out is required")?;
        let expected_source_sha256 =
            expected_source_sha256.ok_or("--expected-source-sha256 is required")?;
        if expected_k == 0 {
            return Err("--k must be positive".into());
        }

        Ok(Self {
            source_path,
            output_path,
            expected_source_sha256,
            expected_k,
        })
    }
}

fn print_usage() {
    println!(
        "usage: cargo run -p halo2-decryption-proof-keygen --bin downsample_srs -- \\
         --source SOURCE --out assets/srs_k14.bin --expected-source-sha256 HEX [--k {EXPECTED_K}]"
    );
}

fn required_arg<'a>(
    args: &'a [String],
    index: usize,
    flag: &'static str,
) -> Result<&'a str, Box<dyn Error>> {
    args.get(index)
        .map(String::as_str)
        .ok_or_else(|| format!("{flag} requires a value").into())
}

fn parse_sha256_hex(input: &str) -> Result<[u8; 32], Box<dyn Error>> {
    if input.len() != 64 || !input.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected SHA-256 digest as 64 hex characters".into());
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(input, &mut out)?;
    Ok(out)
}

fn sha256_file(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 1024 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_decryption_proof_circuit::artifacts::EXPECTED_SRS_SHA256;

    #[test]
    fn checked_in_downsampled_srs_matches_pinned_digest_and_k() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../assets/srs_k14.bin");
        assert_eq!(
            sha256_file(&path).expect("SRS hash computes"),
            EXPECTED_SRS_SHA256
        );

        let mut reader = BufReader::new(File::open(&path).expect("SRS opens"));
        let params = ParamsKZG::<Bn256>::read_custom(&mut reader, SRS_SERDE_FORMAT)
            .expect("SRS parses as raw ParamsKZG<Bn256>");
        assert_eq!(params.k(), EXPECTED_K);
    }
}
