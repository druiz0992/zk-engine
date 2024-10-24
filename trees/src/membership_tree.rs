use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use std::collections::HashMap;

use crate::tree::Position;

pub mod append;
pub mod membership;

pub use membership::MembershipTree;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Node<F: PrimeField>(pub F);

#[derive(Debug, Clone, PartialEq, Eq)]
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
