use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use std::collections::HashMap;

use crate::tree::Position;

pub mod append;

use super::membership_path::MembershipPath;
use super::AppendTree;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree<F: PrimeField, const H: usize> {
    root: F,
    leaf_count: u64,
    inner: HashMap<Position, F>,
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> Default for Tree<F, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> Tree<F, H> {
    pub fn new() -> Self {
        let root = F::zero();
        let leaf_count = 0;
        let inner = HashMap::new();
        Self {
            root,
            leaf_count,
            inner,
        }
    }

    pub fn root(&self) -> F {
        self.root
    }
}

// Trait includes method for obtaining a membership witness to proof membership
pub trait MembershipTree<const H: usize>: AppendTree<H> {
    type Field: PrimeField;

    fn membership_witness(&self, leaf_index: usize) -> Option<MembershipPath<Self::F>> {
        if leaf_index >= self.leaf_count() as usize {
            return None;
        }

        let mut curr_position = Position::new(leaf_index, 0);
        let mut witness_path = MembershipPath::new();
        witness_path.append(self.sibling_node(curr_position));

        for _i in 1..H {
            // Move up one level in the tree
            curr_position = Self::move_up(curr_position);
            // Append the sibling node to the path
            witness_path.append(self.sibling_node(curr_position));
        }

        Some(witness_path)
    }
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> MembershipTree<H> for Tree<F, H> {
    type Field = F;
}

#[cfg(test)]
mod test {
    use super::*;
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
        let tree = Tree::<ark_bn254::Fr, 4>::from_leaves(leaves);

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
        assert_eq!(witness_hash, tree.root);
    }
}
