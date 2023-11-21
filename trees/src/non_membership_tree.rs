use std::collections::HashMap;

use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use rayon::prelude::*;

use crate::{
    membership_tree::MembershipTree,
    tree::{AppendTree, Position},
};

pub trait NonMembershipTree: MembershipTree {
    fn non_membership_witness(&self, leaf: Self::Field) -> Option<Vec<Self::Field>>;
    fn update_low_nullifier(&mut self, leaf: Self::Field);
}

#[derive(Clone, Debug, Default)]
pub struct IndexedNode<F: PrimeField> {
    pub value: F,
    pub next_index: usize,
    pub next_value: F,
}

impl<F: PrimeField> IndexedNode<F> {
    pub fn new(value: F, next_index: usize, next_value: F) -> Self {
        Self {
            value,
            next_index,
            next_value,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedIndexedNode<F: PrimeField> {
    pub tree_index: usize,
    pub node: IndexedNode<F>,
}

#[derive(Clone, Debug)]
pub struct IndexedMerkleTree<F: PrimeField, const H: usize> {
    pub inner: HashMap<Position, F>,           // leaf position indexed
    pub sorted_vec: Vec<SortedIndexedNode<F>>, //leaf position indexed
    pub leaf_count: u64,
    pub root: F,
}

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> Default
    for IndexedMerkleTree<F, H>
{
    fn default() -> Self {
        Self::new()
    }
}
impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> IndexedMerkleTree<F, H> {
    pub fn new() -> Self {
        let mut inner = HashMap::new();
        let zeroth_node: IndexedNode<F> = Default::default();
        let sorted_vec = vec![SortedIndexedNode {
            tree_index: 0,
            node: zeroth_node.clone(),
        }];
        let leaf_count = 1;
        let zeroth_node_hash = Self::leaf_hash(zeroth_node);
        inner.insert(Default::default(), zeroth_node_hash);
        let root = Self::get_root_in_place(vec![zeroth_node_hash]);
        Self {
            inner,
            sorted_vec,
            leaf_count,
            root,
        }
    }

    pub fn leaf_hash(leaf: IndexedNode<F>) -> F {
        let poseidon: Poseidon<F> = Poseidon::new();
        let index_f = F::from(leaf.next_index as u64);
        poseidon.hash_unchecked(vec![leaf.value, index_f, leaf.next_value])
    }

    pub fn find_predecessor(&self, val: F) -> SortedIndexedNode<F> {
        // A better way would be to use a binary search
        // This unwrap is safe because there is always a zeroth_node in the list
        let max_node = self.sorted_vec.last().unwrap();
        if val > max_node.node.value {
            return max_node.clone(); // The predecessor is the max_node
        }
        // Else the predecessor is array and filtered_window.length > 0
        let filtered_window = self
            .sorted_vec
            .par_windows(2)
            .filter(|window| window[0].node.value <= val && val < window[1].node.value)
            .collect::<Vec<_>>();
        filtered_window[0][0].clone()
    }
}

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

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> MembershipTree
    for IndexedMerkleTree<F, H>
{
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

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> NonMembershipTree
    for IndexedMerkleTree<F, H>
{
    fn non_membership_witness(&self, leaf: Self::Field) -> Option<Vec<Self::Field>> {
        // find predecessor
        let low_nullifier = self.find_predecessor(leaf);
        // It is a member therefore return None
        if low_nullifier.node.next_value == leaf {
            return None;
        }
        // Return membership proof that low_nullifier is in tree
        self.membership_witness(low_nullifier.tree_index)
    }
    fn update_low_nullifier(&mut self, leaf: F) {
        let poseidon: Poseidon<F> = Poseidon::new();
        let mut low_nullifier = self.find_predecessor(leaf);
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
        let search_val = low_nullifier.node.value;
        for s in self.sorted_vec.iter_mut() {
            if s.node.value == search_val {
                *s = low_nullifier.clone();
            }
        }

        self.update_by_leaf_index(low_nullifier.tree_index);
    }
}

#[cfg(test)]
mod test {
    use super::{IndexedMerkleTree, IndexedNode, NonMembershipTree};
    use crate::membership_tree::MembershipTree;
    use crate::tree::{AppendTree, Position};
    use ark_bn254::Fr;
    use ark_ff::{PrimeField, Zero};
    use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

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

    #[test]
    fn test_non_set_membership() {
        test_non_set_membership_helper::<ark_bn254::Fr, 2>();
    }

    fn test_non_set_membership_helper<F: PrimeField + PoseidonParams<Field = F>, const H: usize>() {
        // Try with a 6 element tree of height 4, 5 is not in the list
        let nodes = vec![
            IndexedNode::new(F::from(1u128), 1, F::from(2u128)),
            IndexedNode::new(F::from(2u128), 2, F::from(3u128)),
            IndexedNode::new(F::from(3u128), 3, F::from(4u128)),
            IndexedNode::new(F::from(4u128), 4, F::from(6u128)),
            IndexedNode::new(F::from(6u128), 5, F::from(7u128)),
            IndexedNode::new(F::from(7u128), 0, F::from(0u128)),
        ];
        let node_values = nodes.into_iter().map(|node| node.value).collect::<Vec<_>>();
        let indexed_tree = IndexedMerkleTree::<F, H>::from_leaves(node_values);

        let witness = indexed_tree.non_membership_witness(F::from(5u128)).unwrap();
        let low_nullifer = indexed_tree.find_predecessor(F::from(5u128));
        let low_nullifier_hash = indexed_tree.get_node(Position::new(low_nullifer.tree_index, 0));
        let poseidon = Poseidon::<F>::new();
        assert!(low_nullifer.node.next_value > F::from(5u128));
        assert!(low_nullifer.node.value < F::from(5u128));
        let witness_hash =
            witness
                .into_iter()
                .enumerate()
                .fold(low_nullifier_hash, |acc, (i, curr)| {
                    if low_nullifer.tree_index >> i & 1 == 0 {
                        poseidon.hash_unchecked(vec![acc, curr])
                    } else {
                        poseidon.hash(vec![curr, acc]).unwrap()
                    }
                });
        assert_eq!(witness_hash, indexed_tree.root);
    }
}
