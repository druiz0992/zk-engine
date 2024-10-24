use std::collections::HashMap;

use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use rayon::prelude::*;

use super::tree::AppendTree;
use crate::tree::Position;

mod append;
mod membership;
mod non_membership;

pub use non_membership::NonMembershipTree;

#[derive(Clone, Copy, Debug, Default)]
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
