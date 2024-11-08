use ark_ff::PrimeField;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

use crate::{
    membership_tree::MembershipTree,
    tree::{AppendTree, Position},
};

use super::IndexedMerkleTree;
use crate::membership_path::MembershipPath;
use crate::non_membership_tree::NonMembershipTree;

impl<F: PrimeField + PoseidonParams<Field = F>, const H: usize> NonMembershipTree<H>
    for IndexedMerkleTree<F, H>
{
    fn non_membership_witness(&self, leaf: Self::Field) -> Option<MembershipPath<Self::Field>> {
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
    use super::{IndexedMerkleTree, NonMembershipTree};
    use crate::non_membership_tree::IndexedNode;
    use crate::tree::{AppendTree, Position};
    use ark_ff::PrimeField;
    use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};

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
