use crate::ports::prover::SequencerProver;
use crate::ports::storage::{GlobalStateStorage, TransactionStorage};
use crate::usecase::block::TransactionProcessor;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::{crypto::poseidon::constants::PoseidonParams, structs::Transaction};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_utils::field_switching;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use plonk_prover::{
    client::structs::ClientPubInput,
    rollup::circuits::client_input::{self, ClientInput},
};
use tokio::sync::MutexGuard;
use trees::{
    membership_tree::{MembershipTree, Tree},
    non_membership_tree::IndexedMerkleTree,
};
use zk_macros::prover_bounds;

use super::BuildBlockError;

// pub struct ClientInput<P, V, c nst C: usize, const N: usize>
// where
//     P: Pairing,
//     V: Pairing<ScalarField = P::BaseField>,
//     <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
//     <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
// {
//     proof: Proof<V>,
//     nullifiers: [V::ScalarField; N], // List of nullifiers in transaction
//     commitments: [V::ScalarField; C], // List of commitments in transaction
//     commitment_tree_root: [P::ScalarField; N], // Tree root for comm membership
//     path_comm_tree_root_to_global_tree_root: [[P::ScalarField; 8]; N],
//     path_comm_tree_index: [P::ScalarField; N],
//     low_nullifier: [IndexedNode<P::ScalarField>; N],
//     low_nullifier_indices: [P::ScalarField; N],
//     low_nullifier_mem_path: [[P::ScalarField; 32]; N], // Path for nullifier non membership
//     vk_paths: [P::ScalarField; 1],
//     vk_path_index: P::ScalarField,
//     vk: VerifyingKey<V>,
//     ciphertext: [V::ScalarField; 3],
// }
//

#[prover_bounds]
pub async fn build_client_inputs<
    P,
    V,
    SW,
    VSW,
    Storage: TransactionStorage<V>
        + GlobalStateStorage<
            CommitmentTree = Tree<V::BaseField, 8>,
            VkTree = Tree<V::BaseField, 8>,
            NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
        >,
    Proof: SequencerProver<V, VSW, P, SW>,
>(
    db_locked: MutexGuard<'_, Storage>,
    prover: MutexGuard<'_, Proof>,
    processor: MutexGuard<'_, TransactionProcessor<P, V, VSW>>,
    transactions: Vec<Transaction<V>>,
) -> Result<Vec<ClientInput<V>>, BuildBlockError> {
    let vk_tree = db_locked.get_vk_tree();
    let mut client_inputs = Vec::new();
    let mut nullifier_tree = db_locked.get_global_nullifier_tree();
    let mut global_comm_roots: Vec<V::ScalarField> = Vec::new();
    for transaction in &transactions {
        let transaction_type = &transaction.circuit_type;
        let vk_info = prover
            .get_vk(transaction_type.clone())
            .ok_or(BuildBlockError::VksNotFound)?;
        let public_input: ClientPubInput<<V as Pairing>::ScalarField> = transaction.into();
        let low_nullifier_info = client_input::update_nullifier_tree::<V, 32>(
            &mut nullifier_tree,
            &public_input.nullifiers,
        );
        let dispatcher = processor
            .get_dispatcher(transaction_type)
            .ok_or(BuildBlockError::DispatcherNotFound)?;
        let (vk, vk_idx) = vk_info;
        let mut client_input = dispatcher.generate_client_input_for_sequencer(
            transaction.proof.clone(),
            vk,
            &public_input,
            &low_nullifier_info,
        );

        client_input.vk_paths = vk_tree
            .membership_witness(vk_idx)
            .ok_or(BuildBlockError::VksNotFound)?
            .as_vec();
        client_input.vk_path_index = V::BaseField::from(vk_idx as u32);
        client_inputs.push(client_input);
        if low_nullifier_info.is_some() {
            global_comm_roots.push(field_switching(&public_input.commitment_root[0]));
            //TODO: this is principle is only fot transfers
        }
    }
    Ok(client_inputs)
}
