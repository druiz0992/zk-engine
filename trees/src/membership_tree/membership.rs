use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;

use super::Tree;
use crate::membership_path::MembershipPath;
use crate::tree::{AppendTree, Position};

// Trait includes method for obtaining a membership witness to proof membership
pub trait MembershipTree {
    type Field: PrimeField;

    fn membership_witness(&self, leaf: usize) -> Option<MembershipPath<Self::Field>>;
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> MembershipTree for Tree<F, H> {
    type Field = F;

    fn membership_witness(&self, leaf_index: usize) -> Option<MembershipPath<Self::Field>> {
        if leaf_index >= self.leaf_count as usize {
            return None;
        }
        let mut curr_position = Position::new(leaf_index, 0);
        let mut witness_path = MembershipPath::new(self.sibling_node(curr_position));
        for _i in 1..H {
            // Go up one level
            curr_position = Tree::<F, H>::move_up(curr_position);
            // Append sibling
            witness_path.append(self.sibling_node(curr_position));
        }
        Some(witness_path)
    }
}

#[cfg(test)]
mod test {
    use super::MembershipTree;
    use crate::tree::AppendTree;
    use ark_ff::PrimeField;
    use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

    // Single threaded checker, expects subtree to be a power of 2
    #[allow(dead_code)]
    fn hash_subtree_helper<F: PoseidonParams<Field = F> + PrimeField>(subtree: Vec<F>) -> F {
        let poseidon: Poseidon<F> = Poseidon::new();
        match subtree[..] {
            [left, right] => {
                if left.is_zero() {
                    F::zero()
                } else {
                    poseidon.hash_unchecked(vec![left, right])
                }
            }
            _ => {
                let left = subtree[0..subtree.len() / 2].to_vec();
                let left_root = hash_subtree_helper(left);
                if left_root.is_zero() {
                    return F::zero();
                }
                let right = subtree[subtree.len() / 2..].to_vec();
                let right_root = hash_subtree_helper(right);
                poseidon.hash_unchecked(vec![left_root, right_root])
            }
        }
    }

    #[test]
    fn test_set_membership() {
        // Try with a 6 element tree of height 4
        let leaves = vec![
            ark_bn254::Fr::from(1u128),
            ark_bn254::Fr::from(2u128),
            ark_bn254::Fr::from(3u128),
            ark_bn254::Fr::from(4u128),
            ark_bn254::Fr::from(5u128),
            ark_bn254::Fr::from(6u128),
        ];
        let tree = super::Tree::<ark_bn254::Fr, 4>::from_leaves(leaves);
        let witness = tree.membership_witness(2).unwrap();
        let poseidon = Poseidon::<ark_bn254::Fr>::new();
        let witness_hash =
            witness
                .into_iter()
                .enumerate()
                .fold(ark_bn254::Fr::from(3u128), |acc, (i, curr)| {
                    if 2 >> i & 1 == 0 {
                        poseidon.hash_unchecked(vec![acc, curr])
                    } else {
                        poseidon.hash(vec![curr, acc]).unwrap()
                    }
                });
        assert_eq!(witness_hash, tree.root.0);
    }
}
