use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use std::collections::HashMap;

use crate::tree::{AppendTree, Position};

pub trait MembershipTree {
    type Field: PrimeField;
    fn membership_witness(&self, leaf: usize) -> Option<Vec<Self::Field>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Node<F: PrimeField>(pub F);
pub struct Tree<F: PrimeField, const H: usize> {
    pub root: Node<F>,
    pub leaf_count: u64,
    pub inner: HashMap<Position, Node<F>>,
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
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> AppendTree<H> for Tree<F, H> {
    type F = F;
    fn from_leaves(leaves: Vec<F>) -> Self {
        let leaves_len = leaves.len();
        let inner = HashMap::with_capacity(leaves_len * 2 + 1);
        let leaf_count = leaves_len as u64;
        let mut tree = Self {
            root: Default::default(),
            leaf_count,
            inner,
        };
        let root = tree.add_leaves(leaves);
        tree.root = Node(root);
        tree
    }

    // There will be a better way to implement this when we store intermediary nodes
    fn append_leaf(&mut self, leaf: Self::F) {
        let new_leaf_pos = Position::new(self.leaf_count as usize, 0);
        self.inner.insert(new_leaf_pos, Node(leaf));
        self.update_by_leaf_index(self.leaf_count as usize);
        self.leaf_count += 1;
    }

    fn get_node(&self, position: Position) -> Self::F {
        if let Some(node) = self.inner.get(&position) {
            node.0
        } else {
            Self::F::zero()
        }
    }

    fn update_node(&mut self, position: Position, new_node: Self::F) {
        if let Some(node) = self.inner.get_mut(&position) {
            node.0 = new_node;
        }
    }
    fn insert_node(&mut self, position: Position, new_node: Self::F) {
        self.inner.insert(position, Node(new_node));
    }

    fn update_root(&mut self, new_node: Self::F) {
        self.root = Node(new_node);
    }
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> MembershipTree for Tree<F, H> {
    type Field = F;

    fn membership_witness(&self, leaf_index: usize) -> Option<Vec<Self::Field>> {
        if leaf_index >= self.leaf_count as usize {
            return None;
        }
        let mut curr_position = Position::new(leaf_index, 0);
        let mut witness_path = vec![self.sibling_node(curr_position)];
        for i in 1..H {
            // Go up one level
            curr_position = Position::new(curr_position.index / 2, i);
            // Append sibling
            witness_path.push(self.sibling_node(curr_position));
        }
        Some(witness_path)
    }
}

#[cfg(test)]
mod test {
    use crate::membership_tree::MembershipTree;
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
        assert_eq!(tree.inner.len(), 6 + H - 2);
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
        assert_eq!(tree.root.0, leaves_hash);
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
        assert_eq!(tree.root.0, leaves_hash);
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
