use std::collections::HashMap;

use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use rayon::prelude::*;

pub struct Node<F: PrimeField>(pub F);

pub struct Tree<F: PrimeField, const H: usize> {
    pub root: Node<F>,
    pub leaf_count: u64,
    pub inner: HashMap<u16, Node<F>>,
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> Default for Tree<F, H> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> Tree<F, H> {
    pub fn new() -> Self {
        let root = Node(F::zero());
        let leaf_count = 0;
        let inner = HashMap::new();
        Self {
            root,
            leaf_count,
            inner,
        }
    }

    pub fn from_leaves(leaves: Vec<F>) -> Self {
        let leaves_len = leaves.len();
        let tree_leaves = leaves.clone();
        let root = Self::from_leaves_in_place(tree_leaves);
        let leaf_count = leaves_len as u64;
        let inner = HashMap::from_iter((0..leaves_len).map(|i| (i as u16, Node(leaves[i]))));
        Self {
            root: Node(root),
            leaf_count,
            inner,
        }
    }

    pub fn from_leaves_in_place(mut leaves: Vec<F>) -> F {
        let poseidon: Poseidon<F> = Poseidon::new();
        assert!(leaves.len() <= 1 << H, "Too Many leaves for tree");
        // leaves.resize(1 << H, F::zero());

        for _ in 0..H {
            leaves = leaves
                .into_par_iter()
                .chunks(2)
                .map(|chunk| match chunk.as_slice() {
                    [left] => {
                        if left.is_zero() {
                            return F::zero();
                        }
                        poseidon.hash_unchecked(vec![*left, F::zero()])
                    }
                    _ => {
                        if chunk[0].is_zero() {
                            return F::zero();
                        }
                        poseidon.hash_unchecked(chunk)
                    }
                })
                .collect();
        }
        leaves[0]
    }
}

#[cfg(test)]
mod test {
    use ark_ff::PrimeField;
    use ark_std::rand::Rng;
    use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

    // Single threaded checker, expects subtree to be a power of 2
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
    fn test_merkle_tree_from_leaves() {
        test_from_leaves_helper::<ark_bn254::Fr, 2>();
        test_from_leaves_helper::<ark_bn254::Fr, 3>();
        test_from_leaves_helper::<ark_bn254::Fr, 16>();
    }

    fn test_from_leaves_helper<F: PoseidonParams<Field = F> + PrimeField, const H: usize>() {
        // Try an Even number of leaves
        let leaves = vec![
            F::from(1u128),
            F::from(2u128),
            F::from(3u128),
            F::from(4u128),
        ];
        let poseidon = Poseidon::<F>::new();
        let mut leaves_hash = poseidon
            .hash(vec![
                poseidon.hash(vec![F::from(1u128), F::from(2u128)]).unwrap(),
                poseidon.hash(vec![F::from(3u128), F::from(4u128)]).unwrap(),
            ])
            .unwrap();
        for _ in 0..(H - leaves.len().trailing_zeros() as usize) {
            leaves_hash = poseidon.hash(vec![leaves_hash, F::zero()]).unwrap();
        }

        let tree = super::Tree::<F, H>::from_leaves(leaves.clone());
        assert_eq!(tree.leaf_count, leaves.len() as u64);
        assert_eq!(tree.inner.len(), leaves.len());
        assert_eq!(tree.root.0, leaves_hash);

        // Try an ODd number of leaves
        let leaves = vec![F::from(1u128), F::from(2u128), F::from(3u128)];
        let poseidon = Poseidon::<F>::new();
        let mut leaves_hash = poseidon
            .hash(vec![
                poseidon.hash(vec![F::from(1u128), F::from(2u128)]).unwrap(),
                poseidon.hash(vec![F::from(3u128), F::from(0u128)]).unwrap(),
            ])
            .unwrap();
        for _ in 0..(H - 2) {
            leaves_hash = poseidon.hash(vec![leaves_hash, F::zero()]).unwrap();
        }

        let tree = super::Tree::<F, H>::from_leaves(leaves.clone());
        assert_eq!(tree.leaf_count, leaves.len() as u64);
        assert_eq!(tree.inner.len(), leaves.len());
        assert_eq!(tree.root.0, leaves_hash);
    }

    #[test]
    fn test_merkle_tree_from_leaves_random() {
        test_from_random_helper::<ark_bn254::Fr, 2>();
        test_from_random_helper::<ark_bn254::Fr, 3>();
        test_from_random_helper::<ark_bn254::Fr, 4>();
        test_from_random_helper::<ark_bn254::Fr, 5>();
    }

    fn test_from_random_helper<F: PoseidonParams<Field = F> + PrimeField, const H: usize>() {
        use ark_std::rand::SeedableRng;
        use rand_chacha::ChaCha20Rng;

        let mut rng = ChaCha20Rng::seed_from_u64(0u64);
        let max_leaves = 1 << H;
        let leaf_count = rng.gen_range(1..max_leaves);
        let mut leaves: Vec<F> = (0..leaf_count).map(|_| F::rand(&mut rng)).collect();
        let tree = super::Tree::<F, H>::from_leaves(leaves.clone());
        leaves.resize(1 << H, F::zero());
        let helper_hash = hash_subtree_helper(leaves);
        assert_eq!(helper_hash, tree.root.0);
    }
}
