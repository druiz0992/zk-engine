use std::collections::HashMap;

use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

use super::tree::AppendTree;
use crate::tree::Position;

mod append;
mod membership;
mod non_membership;

use super::membership_path::MembershipPath;
use super::membership_tree::MembershipTree;

#[derive(Clone, Copy, Debug, Default)]
pub struct IndexedNode<F: PrimeField> {
    value: F,
    next_index: usize,
    next_value: F,
}

impl<F: PrimeField> IndexedNode<F> {
    pub fn new(value: F, next_index: usize, next_value: F) -> Self {
        Self {
            value,
            next_index,
            next_value,
        }
    }

    pub fn value(&self) -> F {
        self.value
    }

    pub fn next_index(&self) -> u64 {
        self.next_index as u64
    }

    pub fn next_value(&self) -> F {
        self.next_value
    }
}

#[derive(Clone, Debug, Default)]
pub struct SortedIndexedNode<F: PrimeField> {
    pub tree_index: usize,
    pub node: IndexedNode<F>,
}

#[derive(Clone, Debug)]
pub struct IndexedMerkleTree<F: PrimeField, const H: usize> {
    inner: HashMap<Position, F>,           // leaf position indexed
    sorted_vec: Vec<SortedIndexedNode<F>>, //leaf position indexed
    leaf_count: u64,
    root: F,
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
            node: zeroth_node,
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
        let max_node = self.sorted_vec.last().unwrap();
        if val > max_node.node.value {
            return max_node.clone(); // The predecessor is the max_node
        }

        let find_previous_item =
            |sorted_items: &[SortedIndexedNode<F>], target_value: F| -> SortedIndexedNode<F> {
                let mut low = 0;
                let mut high = sorted_items.len() as isize - 1;

                while low <= high {
                    let mid = (low + high) / 2;

                    if sorted_items[mid as usize].node.value < target_value {
                        low = mid + 1;
                    } else {
                        high = mid - 1;
                    }
                }

                sorted_items[high as usize].clone()
            };

        find_previous_item(&self.sorted_vec, val)
    }

    pub fn root(&self) -> F {
        self.root
    }
}

pub trait NonMembershipTree<const H: usize>: MembershipTree<H> {
    fn non_membership_witness(&self, leaf: Self::Field) -> Option<MembershipPath<Self::Field>>;
    fn update_low_nullifier(&mut self, leaf: Self::Field);
}
