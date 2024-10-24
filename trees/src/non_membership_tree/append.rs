use std::collections::HashMap;

use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use rayon::prelude::*;

use super::{IndexedMerkleTree, IndexedNode, SortedIndexedNode};
use crate::tree::{AppendTree, Position};

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> AppendTree<H>
    for IndexedMerkleTree<F, H>
{
    type F = F;

    // There will be a better way to implement this when we store intermediary nodes
    fn append_leaf(&mut self, leaf: Self::F) {
        let poseidon: Poseidon<F> = Poseidon::new();
        let mut low_nullifier = self.find_predecessor(leaf);
        let new_node = IndexedNode {
            value: leaf,
            next_value: low_nullifier.node.next_value,
            next_index: low_nullifier.node.next_index,
        };
        let new_node_hash = poseidon.hash_unchecked(vec![
            leaf,
            F::from(low_nullifier.node.next_index as u64),
            low_nullifier.node.next_value,
        ]);
        low_nullifier.node.next_index = self.leaf_count as usize;
        low_nullifier.node.next_value = leaf;

        let low_nullifier_pos = Position::new(low_nullifier.tree_index, 0);

        if let Some(low_nullifier_node) = self.inner.get_mut(&low_nullifier_pos) {
            *low_nullifier_node = poseidon.hash_unchecked(vec![
                low_nullifier.node.value,
                F::from(low_nullifier.node.next_index as u64),
                low_nullifier.node.next_value,
            ]);
        } else {
            panic!("Think of an error if we cant find the low_nullifier");
        }

        self.inner
            .insert(Position::new(self.leaf_count as usize, 0), new_node_hash);
        self.update_by_leaf_index(low_nullifier.tree_index);
        self.update_by_leaf_index(self.leaf_count as usize);

        let search_val = low_nullifier.node.value;
        for s in self.sorted_vec.iter_mut() {
            if s.node.value == search_val {
                *s = low_nullifier.clone();
            }
        }

        self.sorted_vec.push(SortedIndexedNode {
            tree_index: self.leaf_count as usize,
            node: new_node,
        });
        self.sorted_vec
            .sort_by(|a, b| a.node.value.cmp(&b.node.value));
        self.leaf_count += 1;
        // Calculate Root here
        self.root = self.get_node(Position::new(0, H));
    }

    // For an empty indexed merkle tree, there should be a zero as the first element
    fn from_leaves(leaves: Vec<Self::F>) -> Self {
        if leaves.is_empty() {
            return Self::new();
        }
        let leaf_count = leaves.len() as u64;
        // Sorted vec is the tuple (insertion_index, val)
        let mut sorted_vec = leaves.into_iter().enumerate().collect::<Vec<_>>();
        // Sort by val.
        sorted_vec.sort_by(|(_, a), (_, b)| a.cmp(b));
        // This is a parallel window of overlapping pairs
        // We assign the next details of the left to that of the right
        // we also maintain original insertion index so we can "un-sort" this after
        // Note this will drop the "last" node which we have to push after
        let mut sorted_nodes = sorted_vec
            .par_windows(2)
            .map(|chunk| match chunk {
                [(original_index, curr_value), (next_index, next_value)] => (
                    *original_index,
                    IndexedNode::new(*curr_value, *next_index, *next_value),
                ),
                _ => unreachable!(),
            })
            .collect::<Vec<_>>();

        let last_node = sorted_vec.last().unwrap();
        // Push last node onto sorted nodes
        sorted_nodes.push((
            last_node.0,
            IndexedNode::new(last_node.1, 0, Self::F::zero()),
        ));

        // Before un-sorting, create a sorted IndexedNode vector that will help with appending
        // other tree operations later.
        let sorted_vec = sorted_nodes
            .clone()
            .into_iter()
            .map(|(tree_index, node)| SortedIndexedNode { tree_index, node })
            .collect();

        // unsort the array before we insert into the tree (so it matches the original order)
        sorted_nodes.sort_by(|(i, _), (j, _)| i.cmp(j));
        // Hash the nodes into leaves.
        let leaf_hashes = sorted_nodes
            .clone()
            .into_par_iter()
            .map(|(_, node)| Self::leaf_hash(node))
            .collect::<Vec<_>>();

        // Calculate the root
        // let root: Self::F = Self::get_root_in_place(leaf_hashes);
        // Insert into tree
        let inner = HashMap::with_capacity(leaf_count as usize * 2 + 1);
        // let inner: HashMap<usize, IndexedNode<F>> = HashMap::from_iter(sorted_nodes.into_iter());
        let mut tree = Self {
            inner,
            sorted_vec,
            leaf_count,
            root: Default::default(),
        };
        let root = tree.add_leaves(leaf_hashes);
        tree.root = root;
        tree
    }

    fn get_node(&self, position: Position) -> Self::F {
        if let Some(node) = self.inner.get(&position) {
            *node
        } else {
            F::zero()
        }
    }

    fn update_node(&mut self, position: Position, new_node: Self::F) {
        if let Some(node) = self.inner.get_mut(&position) {
            *node = new_node
        } else {
            self.inner.insert(position, new_node);
        }
    }

    fn insert_node(&mut self, position: Position, new_node: Self::F) {
        self.inner.insert(position, new_node);
    }

    fn update_root(&mut self, new_node: Self::F) {
        self.root = new_node
    }
}

#[cfg(test)]
mod test {
    use super::{IndexedMerkleTree, IndexedNode};
    use crate::tree::AppendTree;
    use ark_bn254::Fr;
    use ark_ff::PrimeField;
    use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

    #[test]
    fn test_indexed_hash() {
        test_indexed_hash_helper::<Fr, 2>();
        test_indexed_hash_helper_unordered::<Fr, 2>();
    }
    fn test_indexed_hash_helper<F: PrimeField + PoseidonParams<Field = F>, const H: usize>() {
        let poseidon = Poseidon::<F>::new();
        let nodes = vec![
            IndexedNode::new(F::from(1u64), 1, F::from(2u64)),
            IndexedNode::new(F::from(2u64), 2, F::from(3u64)),
            IndexedNode::new(F::from(3u64), 0, F::from(0u64)),
        ];
        let node_values = nodes
            .clone()
            .into_iter()
            .map(|node| node.value)
            .collect::<Vec<_>>();
        let leaves = nodes
            .into_iter()
            .map(|node| {
                poseidon.hash_unchecked(vec![
                    node.value,
                    F::from(node.next_index as u64),
                    node.next_value,
                ])
            })
            .collect::<Vec<_>>();
        let indexed_tree = IndexedMerkleTree::<F, H>::from_leaves(node_values);
        let mut expected_root = poseidon.hash_unchecked(vec![
            poseidon.hash_unchecked(vec![leaves[0], leaves[1]]),
            poseidon.hash_unchecked(vec![leaves[2], F::from(0u64)]),
        ]);
        for _ in 0..(H - 2) {
            expected_root = poseidon.hash_unchecked(vec![expected_root, F::from(0u64)]);
        }
        assert_eq!(indexed_tree.root, expected_root);
    }
    fn test_indexed_hash_helper_unordered<
        F: PrimeField + PoseidonParams<Field = F>,
        const H: usize,
    >() {
        let poseidon = Poseidon::<F>::new();
        let nodes = vec![
            IndexedNode::new(F::from(1u64), 2, F::from(2u64)),
            IndexedNode::new(F::from(3u64), 0, F::from(0u64)),
            IndexedNode::new(F::from(2u64), 1, F::from(3u64)),
        ];
        let node_values = nodes
            .clone()
            .into_iter()
            .map(|node| node.value)
            .collect::<Vec<_>>();
        let leaves = nodes
            .into_iter()
            .map(|node| {
                poseidon.hash_unchecked(vec![
                    node.value,
                    F::from(node.next_index as u64),
                    node.next_value,
                ])
            })
            .collect::<Vec<_>>();
        let indexed_tree = IndexedMerkleTree::<F, H>::from_leaves(node_values);
        let mut expected_root = poseidon.hash_unchecked(vec![
            poseidon.hash_unchecked(vec![leaves[0], leaves[1]]),
            poseidon.hash_unchecked(vec![leaves[2], F::from(0u64)]),
        ]);
        for _ in 0..(H - 2) {
            expected_root = poseidon.hash_unchecked(vec![expected_root, F::from(0u64)]);
        }
        assert_eq!(indexed_tree.root, expected_root);
    }

    #[test]
    fn test_append_indexed_tree() {
        test_append_helper::<ark_bn254::Fr, 2>();
        test_append_helper::<ark_bn254::Fr, 3>();
        test_append_helper::<ark_bn254::Fr, 4>();
        test_append_helper::<ark_bn254::Fr, 5>();
    }
    fn test_append_helper<F: PoseidonParams<Field = F> + PrimeField, const H: usize>() {
        let poseidon = Poseidon::<F>::new();
        let nodes = vec![
            IndexedNode::new(F::from(1u64), 1, F::from(2u64)),
            IndexedNode::new(F::from(2u64), 2, F::from(3u64)),
            IndexedNode::new(F::from(3u64), 0, F::from(0u64)),
        ];
        let node_values = nodes
            .clone()
            .into_iter()
            .map(|node| node.value)
            .collect::<Vec<_>>();
        let leaves = nodes
            .into_iter()
            .map(|node| {
                poseidon.hash_unchecked(vec![
                    node.value,
                    F::from(node.next_index as u64),
                    node.next_value,
                ])
            })
            .collect::<Vec<_>>();
        let mut indexed_tree = IndexedMerkleTree::<F, H>::from_leaves(node_values);
        let mut expected_root = poseidon.hash_unchecked(vec![
            poseidon.hash_unchecked(vec![leaves[0], leaves[1]]),
            poseidon.hash_unchecked(vec![leaves[2], F::from(0u64)]),
        ]);
        for _ in 0..(H - 2) {
            expected_root = poseidon.hash_unchecked(vec![expected_root, F::from(0u64)]);
        }
        assert_eq!(indexed_tree.root, expected_root);

        // Append a leaf = 4 to the tree
        let new_leaf = F::from(4u128);
        indexed_tree.append_leaf(new_leaf);
        let nodes = vec![
            IndexedNode::new(F::from(1u64), 1, F::from(2u64)),
            IndexedNode::new(F::from(2u64), 2, F::from(3u64)),
            IndexedNode::new(F::from(3u64), 3, F::from(4u64)),
            IndexedNode::new(F::from(4u128), 0, F::from(0u128)),
        ];
        let node_values = nodes
            .clone()
            .into_iter()
            .map(|node| node.value)
            .collect::<Vec<_>>();
        let leaves = nodes
            .into_iter()
            .map(|node| {
                poseidon.hash_unchecked(vec![
                    node.value,
                    F::from(node.next_index as u64),
                    node.next_value,
                ])
            })
            .collect::<Vec<_>>();
        let indexed_tree = IndexedMerkleTree::<F, H>::from_leaves(node_values);
        let mut expected_root = poseidon.hash_unchecked(vec![
            poseidon.hash_unchecked(vec![leaves[0], leaves[1]]),
            poseidon.hash_unchecked(vec![leaves[2], leaves[3]]),
        ]);
        for _ in 0..(H - 2) {
            expected_root = poseidon.hash_unchecked(vec![expected_root, F::from(0u64)]);
        }
        assert_eq!(indexed_tree.root, expected_root);
    }
}
