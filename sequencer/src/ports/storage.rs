use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::{Block, CircuitType, Transaction};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use trees::{
    membership_tree::MembershipTree, non_membership_tree::NonMembershipTree, tree::AppendTree,
};
use zk_macros::client_bounds;

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
    fn flush_mempool_transactions(&mut self);
}

pub trait BlockStorage<F: PrimeField> {
    fn get_block(&self, blocknumber: u64) -> Option<Block<F>>;
    fn insert_block(&mut self, block: Block<F>);
    fn get_block_count(&self) -> u64;
}

pub trait GlobalStateStorage {
    type CommitmentTree: MembershipTree<8> + AppendTree<8>;
    type VkTree: MembershipTree<8> + AppendTree<8>;
    type NullifierTree: NonMembershipTree<32> + AppendTree<32>;
    fn get_global_commitment_tree(&self) -> Self::CommitmentTree;
    fn store_global_commitment_tree(&mut self, new_tree: Self::CommitmentTree);
    fn get_global_nullifier_tree(&self) -> Self::NullifierTree;
    fn get_vk_tree(&self) -> Self::VkTree;
    fn store_vk_tree(&mut self, vk_tree: Self::VkTree);
}

#[client_bounds]
pub trait Dispatcher<P, V, VSW> {
    fn register(
        &mut self,
        transaction_type: CircuitType,
        processor: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    );
    fn get_dispatcher(
        &self,
        transaction_type: &CircuitType,
    ) -> Option<Box<dyn ClientPlonkCircuit<P, V, VSW>>>;
}
