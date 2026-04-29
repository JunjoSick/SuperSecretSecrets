#!/usr/bin/env bash
#
# Regenerate `circuit/src/poseidon2/params.rs` from the
# `@zkpassport/poseidon2` BN254 constants the TypeScript side already
# depends on. Run from the repo root after a `npm install`.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
SOURCE="$REPO_ROOT/node_modules/@zkpassport/poseidon2/dist/esm/bn254/constants.js"
TARGET="$REPO_ROOT/crates/halo2-decryption-proof/circuit/src/poseidon2/params.rs"

if [ ! -f "$SOURCE" ]; then
    echo "missing $SOURCE — run \`npm install\` from the SuperSecretSecrets/ directory first" >&2
    exit 1
fi

python3 - "$SOURCE" "$TARGET" <<'PY'
import re
import sys

source_path, target_path = sys.argv[1], sys.argv[2]

with open(source_path, "r", encoding="utf-8") as f:
    text = f.read()

hex_values = re.findall(r"0x[0-9a-fA-F]{64}", text)
assert len(hex_values) == 4 + 16 + 64 * 4, len(hex_values)

diag = hex_values[0:4]
rc = hex_values[20:]
assert len(rc) == 256

lines = [
    "// Auto-generated from @zkpassport/poseidon2 v0.6.x bn254 constants.",
    "// Do not edit by hand — regenerate via",
    "// `crates/halo2-decryption-proof/scripts/regenerate-poseidon2-constants.sh`.",
    "",
    "use halo2curves::bn256::Fr;",
    "use halo2curves::ff::{Field, PrimeField};",
    "",
    "pub const STATE_WIDTH: usize = 4;",
    "pub const ROUND_CONSTANTS_COUNT: usize = 64;",
    "",
    "pub const MAT_DIAG4_M_1_HEX: [&str; 4] = [",
]
for v in diag:
    lines.append(f'    "{v}",')
lines.append("];")
lines.append("")
lines.append("pub const ROUND_CONSTANTS_HEX: [[&str; STATE_WIDTH]; ROUND_CONSTANTS_COUNT] = [")
for r in range(64):
    lines.append("    [")
    for v in rc[r * 4:(r + 1) * 4]:
        lines.append(f'        "{v}",')
    lines.append("    ],")
lines.append("];")
lines.append("")
lines.append('pub static MAT_DIAG4_M_1: once_cell_polyfill::ConstArray<Fr, STATE_WIDTH> =')
lines.append('    once_cell_polyfill::ConstArray::new(|| {')
lines.append('        let mut out = [Fr::ZERO; STATE_WIDTH];')
lines.append('        for (i, hex_str) in MAT_DIAG4_M_1_HEX.iter().enumerate() {')
lines.append('            out[i] = parse_hex_fr(hex_str);')
lines.append('        }')
lines.append('        out')
lines.append('    });')
lines.append("")
lines.append('static ROUND_CONSTANTS: once_cell_polyfill::ConstArray<')
lines.append('    [Fr; STATE_WIDTH],')
lines.append('    ROUND_CONSTANTS_COUNT,')
lines.append('> = once_cell_polyfill::ConstArray::new(|| {')
lines.append('    let mut rounds = [[Fr::ZERO; STATE_WIDTH]; ROUND_CONSTANTS_COUNT];')
lines.append('    for (r, row) in ROUND_CONSTANTS_HEX.iter().enumerate() {')
lines.append('        for (i, hex_str) in row.iter().enumerate() {')
lines.append('            rounds[r][i] = parse_hex_fr(hex_str);')
lines.append('        }')
lines.append('    }')
lines.append('    rounds')
lines.append('});')
lines.append("")
lines.append('pub fn round_constant(round: usize, column: usize) -> Fr {')
lines.append('    ROUND_CONSTANTS[round][column]')
lines.append('}')
lines.append("")
lines.append('fn parse_hex_fr(hex_str: &str) -> Fr {')
lines.append('    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);')
lines.append('    let bytes = hex::decode(stripped).expect("constant is valid hex");')
lines.append('    assert_eq!(bytes.len(), 32, "BN254 scalar constant must be 32 bytes");')
lines.append('    let mut le = [0u8; 32];')
lines.append('    for (i, byte) in bytes.iter().rev().enumerate() {')
lines.append('        le[i] = *byte;')
lines.append('    }')
lines.append('    let repr = <Fr as PrimeField>::Repr::from(le);')
lines.append('    Option::<Fr>::from(Fr::from_repr(repr)).expect("constant fits in BN254 scalar")')
lines.append('}')
lines.append("")
lines.append('mod once_cell_polyfill {')
lines.append('    use core::ops::Deref;')
lines.append('    use std::sync::OnceLock;')
lines.append("")
lines.append('    pub struct ConstArray<T, const N: usize> {')
lines.append('        cell: OnceLock<[T; N]>,')
lines.append('        init: fn() -> [T; N],')
lines.append('    }')
lines.append("")
lines.append('    impl<T, const N: usize> ConstArray<T, N> {')
lines.append('        pub const fn new(init: fn() -> [T; N]) -> Self {')
lines.append('            Self { cell: OnceLock::new(), init }')
lines.append('        }')
lines.append('    }')
lines.append("")
lines.append('    impl<T, const N: usize> Deref for ConstArray<T, N> {')
lines.append('        type Target = [T; N];')
lines.append('        fn deref(&self) -> &Self::Target { self.cell.get_or_init(self.init) }')
lines.append('    }')
lines.append('}')

with open(target_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")
print(f"wrote {target_path}")
PY
