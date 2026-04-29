//! Mirrors `src/crypto/zk/decryption-proof-relations.ts` for the
//! `sss-v3-poseidon2bn254-vaultroot-only-v1` relation. The 32-byte digest is
//! computed exactly the same way the TS layer does, and a divergence will
//! surface in the unit test under `tests/relation_digest.rs`.

use sha2::{Digest, Sha256};

pub const RELATION_DIGEST_DOMAIN: &str = "SSS/v3/decryption-proof/relation-digest/v1";
pub const RELATION_V1_VAULTROOT_ONLY_ID: &str = "sss-v3-poseidon2bn254-vaultroot-only-v1";

pub const RELATION_V1_FULL_ID: &str =
    "sss-v3-mlkem768-hkdfsha256-aes256gcm-poseidon2bn254-vaultroot-nopass-v1";

pub const RELATION_DIGEST_BYTES: usize = 32;

/// `sha256(u16len(domain) || domain || u16len(relation_id) || relation_id)`,
/// matching `digestDecryptionProofRelation` in the TS package.
pub fn relation_digest(relation_id: &str) -> [u8; RELATION_DIGEST_BYTES] {
    let mut hasher = Sha256::new();
    write_u16_length_prefixed(&mut hasher, RELATION_DIGEST_DOMAIN.as_bytes());
    write_u16_length_prefixed(&mut hasher, relation_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; RELATION_DIGEST_BYTES];
    out.copy_from_slice(&digest);
    out
}

pub fn relation_v1_vaultroot_only_digest() -> [u8; RELATION_DIGEST_BYTES] {
    relation_digest(RELATION_V1_VAULTROOT_ONLY_ID)
}

/// Constant alias used in tests. Recomputed at runtime; if you need a
/// `const` value, generate one with the keygen binary and check it in.
pub static RELATION_V1_VAULTROOT_ONLY_DIGEST: once_cell_polyfill::Lazy<
    [u8; RELATION_DIGEST_BYTES],
> = once_cell_polyfill::Lazy::new(relation_v1_vaultroot_only_digest);

fn write_u16_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    let len = u16::try_from(bytes.len()).expect("relation digest component fits in u16");
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
}

mod once_cell_polyfill {
    use std::sync::OnceLock;

    pub struct Lazy<T> {
        cell: OnceLock<T>,
        init: fn() -> T,
    }

    impl<T> Lazy<T> {
        pub const fn new(init: fn() -> T) -> Self {
            Self {
                cell: OnceLock::new(),
                init,
            }
        }
    }

    impl<T> std::ops::Deref for Lazy<T> {
        type Target = T;

        fn deref(&self) -> &Self::Target {
            self.cell.get_or_init(self.init)
        }
    }
}
