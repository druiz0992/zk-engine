use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::PrimeField;
use common::structs::{Block, Transaction};
use trees::{
    membership_tree::MembershipTree, non_membership_tree::NonMembershipTree, tree::AppendTree,
};

pub trait TransactionStorage<P>
where
    P: Pairing,
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    fn get_transaction(&self) -> Option<Transaction<P>>;
    fn insert_transaction(&mut self, transaction: Transaction<P>);
    fn get_mempool_transactions(&self) -> Vec<Transaction<P>>;
    fn get_block_transaction(&self) -> Vec<Transaction<P>>;
    fn get_all_transactions(&self) -> Vec<Transaction<P>>;
}

pub trait BlockStorage<F: PrimeField> {
    fn get_block(&self, blocknumber: u64) -> Option<Block<F>>;
    fn insert_block(&mut self, block: Block<F>);
    fn get_block_count(&self) -> u32;
}

pub trait GlobalStateStorage {
    type CommitmentTree: MembershipTree + AppendTree<8>;
    type VkTree: MembershipTree + AppendTree<2>;
    type NullifierTree: NonMembershipTree + AppendTree<32>;
    fn get_global_commitment_tree(&self) -> Self::CommitmentTree;
    fn get_global_nullifier_tree(&self) -> Self::NullifierTree;
    fn get_vk_tree(&self) -> Self::VkTree;
    fn store_vk_tree(&mut self, vk_tree: Self::VkTree);
}
