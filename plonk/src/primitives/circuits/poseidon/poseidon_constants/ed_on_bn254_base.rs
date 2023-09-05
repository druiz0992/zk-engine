use ark_ed_on_bn254::Fq;

use crate::primitives::circuits::poseidon::{PoseidonParams, MAX_INPUT_LEN};

impl PoseidonParams for Fq {
    const N_ROUND_FULL: usize = 8;

    const N_ROUNDS_PARTIAL: [usize; MAX_INPUT_LEN] = [
        56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
    ];
}
