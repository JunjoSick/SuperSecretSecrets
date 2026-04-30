//! Out-of-circuit Poseidon2-BN254 sponge that matches `@zkpassport/poseidon2`
//! v0.6.x with the `paramsId = sss-v3-poseidon2-bn254-v1` configuration:
//!
//! - state width `t = 4` (rate 3, capacity 1)
//! - S-box exponent `d = 5`
//! - 4 + 4 full rounds, 56 partial rounds (64 round constants total)
//! - external matrix is the fixed t=4 circulant defined in the Poseidon2
//!   reference implementation
//! - internal matrix is `diag(MAT_DIAG4_M_1) + ones(t,t)`
//!
//! The sponge uses the same fixed-length-hashing rule as the JS package:
//!
//! ```text
//! state = [0, 0, 0, iv]   where iv = (input.len() << 64) | (out_len - 1)
//! ```
//!
//! `hash_to_field` here corresponds to `poseidon2Hash` on the JS side.
//!
//! The constants live in [`params`] so the eventual halo2 chip can
//! reuse them without forking the values.

pub mod params;

use halo2_axiom::halo2curves::bn256::Fr;
use halo2_axiom::halo2curves::ff::{Field, PrimeField};

const STATE_WIDTH: usize = 4;
const RATE: usize = STATE_WIDTH - 1;
const FULL_ROUNDS_BEGIN: usize = 4;
const FULL_ROUNDS_END: usize = 4;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS + FULL_ROUNDS_END;

/// Pure permutation (no padding / sponge framing).
pub fn permute(state: &mut [Fr; STATE_WIDTH]) {
    matmul_external(state);

    for r in 0..FULL_ROUNDS_BEGIN {
        add_round_constants(state, r);
        sbox_full(state);
        matmul_external(state);
    }

    let partial_end = FULL_ROUNDS_BEGIN + PARTIAL_ROUNDS;
    for r in FULL_ROUNDS_BEGIN..partial_end {
        state[0] += params::round_constant(r, 0);
        sbox(&mut state[0]);
        matmul_internal(state);
    }

    for r in partial_end..TOTAL_ROUNDS {
        add_round_constants(state, r);
        sbox_full(state);
        matmul_external(state);
    }
}

/// Fixed-length sponge hash. Produces a single field element.
pub fn hash_to_field(inputs: &[Fr]) -> Fr {
    hash_internal(inputs, 1, false)[0]
}

/// Fixed-length sponge hash with `out_len` outputs.
pub fn hash_fixed_length(inputs: &[Fr], out_len: usize) -> Vec<Fr> {
    assert!(out_len >= 1, "Poseidon2 hash output length must be >= 1");
    hash_internal(inputs, out_len, false)
}

fn hash_internal(inputs: &[Fr], out_len: usize, is_variable_length: bool) -> Vec<Fr> {
    let iv_high = (inputs.len() as u128) << 64;
    let iv_low = (out_len.saturating_sub(1)) as u128;
    let iv = u128_to_fr(iv_high | iv_low);

    let mut sponge = Sponge::new(iv);
    for input in inputs {
        sponge.absorb(*input);
    }
    if is_variable_length {
        sponge.absorb(Fr::ONE);
    }
    let mut output = Vec::with_capacity(out_len);
    for _ in 0..out_len {
        output.push(sponge.squeeze());
    }
    output
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Absorb,
    Squeeze,
}

struct Sponge {
    state: [Fr; STATE_WIDTH],
    cache: [Fr; RATE],
    cache_size: usize,
    mode: Mode,
}

impl Sponge {
    fn new(iv: Fr) -> Self {
        let mut state = [Fr::ZERO; STATE_WIDTH];
        state[STATE_WIDTH - 1] = iv;
        Self {
            state,
            cache: [Fr::ZERO; RATE],
            cache_size: 0,
            mode: Mode::Absorb,
        }
    }

    fn perform_duplex(&mut self) -> [Fr; RATE] {
        for i in self.cache_size..RATE {
            self.cache[i] = Fr::ZERO;
        }
        for i in 0..RATE {
            self.state[i] += self.cache[i];
        }
        permute(&mut self.state);
        let mut out = [Fr::ZERO; RATE];
        out.copy_from_slice(&self.state[..RATE]);
        out
    }

    fn absorb(&mut self, input: Fr) {
        match self.mode {
            Mode::Absorb if self.cache_size == RATE => {
                self.perform_duplex();
                self.cache[0] = input;
                self.cache_size = 1;
            }
            Mode::Absorb => {
                self.cache[self.cache_size] = input;
                self.cache_size += 1;
            }
            Mode::Squeeze => {
                self.cache[0] = input;
                self.cache_size = 1;
                self.mode = Mode::Absorb;
            }
        }
    }

    fn squeeze(&mut self) -> Fr {
        if self.mode == Mode::Squeeze && self.cache_size == 0 {
            self.mode = Mode::Absorb;
        }
        if self.mode == Mode::Absorb {
            let new_outputs = self.perform_duplex();
            self.mode = Mode::Squeeze;
            self.cache.copy_from_slice(&new_outputs);
            self.cache_size = RATE;
        }
        let result = self.cache[0];
        for i in 1..self.cache_size {
            self.cache[i - 1] = self.cache[i];
        }
        self.cache_size -= 1;
        self.cache[self.cache_size] = Fr::ZERO;
        result
    }
}

fn sbox(value: &mut Fr) {
    let squared = value.square();
    let quartic = squared.square();
    *value = quartic * *value;
}

fn sbox_full(state: &mut [Fr; STATE_WIDTH]) {
    for value in state.iter_mut() {
        sbox(value);
    }
}

fn add_round_constants(state: &mut [Fr; STATE_WIDTH], round: usize) {
    for (i, value) in state.iter_mut().enumerate() {
        *value += params::round_constant(round, i);
    }
}

/// External matrix `M_E` for t=4 — the fixed circulant from the Poseidon2
/// reference implementation. This matches the explicit unrolled sequence in
/// `@zkpassport/poseidon2`'s `matmulExternal`.
fn matmul_external(state: &mut [Fr; STATE_WIDTH]) {
    let mut t0 = state[0];
    t0 += state[1];
    let mut t1 = state[2];
    t1 += state[3];

    let mut t2 = state[1];
    t2 = t2.double();
    t2 += t1;

    let mut t3 = state[3];
    t3 = t3.double();
    t3 += t0;

    let mut t4 = t1;
    t4 = t4.double();
    t4 = t4.double();
    t4 += t3;

    let mut t5 = t0;
    t5 = t5.double();
    t5 = t5.double();
    t5 += t2;

    let mut t6 = t3;
    t6 += t5;

    let mut t7 = t2;
    t7 += t4;

    state[0] = t6;
    state[1] = t5;
    state[2] = t7;
    state[3] = t4;
}

/// Internal matrix `M_I` for t=4: `diag(MAT_DIAG4_M_1) + ones`. The JS impl
/// computes `state[i] = diag[i] * state[i] + sum(state)`.
fn matmul_internal(state: &mut [Fr; STATE_WIDTH]) {
    let sum = state[0] + state[1] + state[2] + state[3];
    for (i, value) in state.iter_mut().enumerate() {
        *value = *value * params::MAT_DIAG4_M_1[i] + sum;
    }
}

fn u128_to_fr(value: u128) -> Fr {
    let mut le = [0u8; 32];
    le[0..16].copy_from_slice(&value.to_le_bytes());
    let repr = <Fr as PrimeField>::Repr::from(le);
    Option::<Fr>::from(Fr::from_repr(repr)).expect("u128 fits in BN254 scalar")
}
