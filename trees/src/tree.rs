use ark_ff::{PrimeField, Zero};
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use rayon::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Position {
    pub index: usize,  // 0 is the left most
    pub height: usize, // 0 is the leaf layer
}

impl Position {
    pub fn new(index: usize, height: usize) -> Self {
        Self { index, height }
    }
}

pub trait AppendTree<const H: usize> {
    type F: PrimeField + PoseidonParams<Field = Self::F>;

    fn append_leaf(&mut self, leaf: Self::F);
    fn from_leaves(leaves: Vec<Self::F>) -> Self;
    fn get_node(&self, position: Position) -> Self::F;
    fn update_node(&mut self, position: Position, new_node: Self::F);
    fn update_root(&mut self, new_node: Self::F);
    fn insert_node(&mut self, position: Position, new_node: Self::F);

    fn move_up(position: Position) -> Position {
        Position::new(position.index / 2, position.height + 1)
    }

    fn sibling_node(&self, position: Position) -> Self::F {
        let sibling_pos = if position.index % 2 == 0 {
            Position::new(position.index + 1, position.height)
        } else {
            Position::new(position.index - 1, position.height)
        };
        self.get_node(sibling_pos)
    }

    fn siblings(&self, position: Position) -> [Self::F; 2] {
        if position.index % 2 == 0 {
            let right_sibling_pos = Position::new(position.index + 1, position.height);
            return [self.get_node(position), self.get_node(right_sibling_pos)];
        }
        let left_sibling_pos = Position::new(position.index - 1, position.height);
        [self.get_node(left_sibling_pos), self.get_node(position)]
    }

    fn get_root_in_place(mut leaves: Vec<Self::F>) -> Self::F {
        let poseidon: Poseidon<Self::F> = Poseidon::new();
        assert!(leaves.len() <= 1 << H, "Too Many leaves for tree");

        for _ in 0..H {
            leaves = leaves
                .into_par_iter()
                .chunks(2)
                .map(|chunk| match chunk.as_slice() {
                    [left] => {
                        if left.is_zero() {
                            return Self::F::zero();
                        }
                        poseidon.hash_unchecked(vec![*left, Self::F::zero()])
                    }
                    _ => {
                        if chunk[0].is_zero() {
                            return Self::F::zero();
                        }
                        poseidon.hash_unchecked(chunk)
                    }
                })
                .collect();
        }
        leaves[0]
    }
    fn add_leaves(&mut self, leaves: Vec<Self::F>) -> Self::F {
        let poseidon: Poseidon<Self::F> = Poseidon::new();
        let mut leaves = leaves;
        for h in 0..H {
            leaves
                .iter()
                .enumerate()
                .filter(|(_, leaf)| !leaf.is_zero())
                .for_each(|(i, leaf)| self.insert_node(Position::new(i, h), *leaf));
            leaves = leaves
                .into_par_iter()
                .chunks(2)
                .map(|chunk| match chunk.as_slice() {
                    [left] => {
                        if left.is_zero() {
                            return Self::F::zero();
                        }
                        poseidon.hash_unchecked(vec![*left, Self::F::zero()])
                    }
                    _ => {
                        if chunk[0].is_zero() {
                            return Self::F::zero();
                        }
                        poseidon.hash_unchecked(chunk)
                    }
                })
                .collect();
        }
        self.insert_node(Position::new(0, H), leaves[0]);
        leaves[0]
    }
    fn update_by_leaf_index(&mut self, leaf_index: usize) {
        let leaf_position = Position::new(leaf_index, 0);
        let mut siblings = self.siblings(leaf_position);
        let poseidon = Poseidon::<Self::F>::new();
        let mut curr_height = 0;
        let mut curr_index = leaf_index;
        let mut curr_hash = poseidon.hash_unchecked(siblings.to_vec());
        while curr_height <= H {
            curr_height += 1;
            curr_index /= 2;
            self.update_node(Position::new(curr_index, curr_height), curr_hash);
            siblings = self.siblings(Position::new(curr_index, curr_height));

            curr_hash = poseidon.hash_unchecked(siblings.to_vec());
        }
        // Update root
        self.update_root(self.get_node(Position::new(0, H)));
    }
}
