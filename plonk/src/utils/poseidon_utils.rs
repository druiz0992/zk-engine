use ark_ff::PrimeField;
use common::crypto::crypto_errors::CryptoError;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use trees::MembershipPath;

const COMMITMENT_LEN: usize = 5;

pub fn build_commitment_hash<F>(commitment: [F; COMMITMENT_LEN]) -> Result<F, CryptoError>
where
    F: PrimeField + PoseidonParams<Field = F>,
{
    let poseidon: Poseidon<F> = Poseidon::new();
    poseidon.hash(commitment.to_vec())
}

pub fn build_tree_root<F>(path: &MembershipPath<F>, hash: F, leaf_index: u64) -> F
where
    F: PrimeField + PoseidonParams<Field = F>,
{
    path.clone()
        .into_iter()
        .enumerate()
        .fold(hash, |a, (i, b)| {
            let poseidon: Poseidon<F> = Poseidon::new();
            let bit_dir = leaf_index >> i & 1;
            if bit_dir == 0 {
                poseidon.hash(vec![a, b]).unwrap()
            } else {
                poseidon.hash(vec![b, a]).unwrap()
            }
        })
}
