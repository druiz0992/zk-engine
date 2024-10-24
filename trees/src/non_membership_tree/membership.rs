use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;

use crate::membership_tree::MembershipTree;

use super::IndexedMerkleTree;

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> MembershipTree<H>
    for IndexedMerkleTree<F, H>
{
    type Field = F;
}

#[cfg(test)]
mod test {
    use super::IndexedMerkleTree;
    use crate::membership_tree::MembershipTree;
    use ark_bn254::Fr;
    use ark_ff::Zero;
    use common::crypto::poseidon::Poseidon;

    #[test]
    fn test_initial_tree_consistent() {
        let initial_tree = IndexedMerkleTree::<Fr, 32>::new();
        let poseidon = Poseidon::<Fr>::new();
        let zeroth_node_hash =
            poseidon.hash_unchecked(vec![Fr::zero(), Fr::from(0u64), Fr::zero()]);
        let mut expected_root = zeroth_node_hash;
        for _ in 0..32 {
            expected_root = poseidon.hash_unchecked(vec![expected_root, Fr::zero()]);
        }
        let witness = initial_tree.membership_witness(0).unwrap();
        let witness_root = witness.into_iter().fold(zeroth_node_hash, |acc, val| {
            poseidon.hash_unchecked(vec![acc, val])
        });
        assert_eq!(witness_root, expected_root);
        assert_eq!(initial_tree.root, expected_root);
    }
}
