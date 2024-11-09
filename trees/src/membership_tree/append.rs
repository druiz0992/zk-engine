use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use std::collections::HashMap;

use super::Tree;
use crate::tree::{AppendTree, Position};

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> AppendTree<H> for Tree<F, H> {
    type F = F;

    fn from_leaves(leaves: Vec<Self::F>) -> Self {
        if leaves.is_empty() {
            return Self::new();
        }
        let leaves_len = leaves.len();
        let inner = HashMap::with_capacity(leaves_len * 2 + 1);
        let leaf_count = leaves_len as u64;
        let mut tree = Self {
            root: Default::default(),
            leaf_count,
            inner,
        };
        let root = tree.add_leaves(leaves);
        tree.root = root;
        tree
    }

    // There will be a better way to implement this when we store intermediary nodes
    fn append_leaf(&mut self, leaf: Self::F) {
        let new_leaf_pos = Position::new(self.leaf_count as usize, 0);
        self.inner.insert(new_leaf_pos, leaf);
        self.update_by_leaf_index(self.leaf_count as usize);
        self.leaf_count += 1;
    }

    fn get_node(&self, position: Position) -> Self::F {
        *self.inner.get(&position).unwrap_or(&Self::F::zero())
    }

    //TODO: should i update if not found?
    fn update_node(&mut self, position: Position, new_node: Self::F) {
        if let Some(node) = self.inner.get_mut(&position) {
            *node = new_node;
        }
    }

    fn insert_node(&mut self, position: Position, new_node: Self::F) {
        self.inner.insert(position, new_node);
    }

    fn update_root(&mut self, new_node: Self::F) {
        self.root = new_node;
    }

    fn leaf_count(&self) -> u64 {
        self.leaf_count
    }
}

#[cfg(test)]
mod test {
    use crate::tree::AppendTree;
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
        assert_eq!(tree.inner.len(), (leaves.len() * 2 - 1) + H - 2);
        assert_eq!(tree.root, leaves_hash);

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
        assert_eq!(tree.inner.len(), 6 + H - 2);
        assert_eq!(tree.root, leaves_hash);
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
        assert_eq!(helper_hash, tree.root);
    }

    #[test]
    fn test_append_merkle_tree() {
        test_append_helper::<ark_bn254::Fr, 2>();
        test_append_helper::<ark_bn254::Fr, 3>();
        test_append_helper::<ark_bn254::Fr, 4>();
        test_append_helper::<ark_bn254::Fr, 5>();
    }
    fn test_append_helper<F: PoseidonParams<Field = F> + PrimeField, const H: usize>() {
        let initial_leaves = vec![F::from(1u128), F::from(2u128), F::from(3u128)];
        let mut tree = super::Tree::<F, H>::from_leaves(initial_leaves);
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
        assert_eq!(tree.root, leaves_hash);
        ark_std::println!("Initial hash is ok");
        // Append a leaf = 4 to the tree
        let new_leaf = F::from(4u128);
        tree.append_leaf(new_leaf);
        let mut leaves_hash = poseidon
            .hash(vec![
                poseidon.hash(vec![F::from(1u128), F::from(2u128)]).unwrap(),
                poseidon.hash(vec![F::from(3u128), F::from(4u128)]).unwrap(),
            ])
            .unwrap();
        for _ in 0..(H - 2) {
            leaves_hash = poseidon.hash(vec![leaves_hash, F::zero()]).unwrap();
        }
        assert_eq!(tree.root, leaves_hash);
    }
}
