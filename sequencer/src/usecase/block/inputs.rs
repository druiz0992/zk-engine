use crate::ports::prover::SequencerProver;
use crate::ports::storage::{GlobalStateStorage, TransactionStorage};
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
use trees::AppendTree;
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
pub async fn build_client_inputs_and_update_nullifier_tree<
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
    db_locked: &MutexGuard<'_, Storage>,
    prover: &MutexGuard<'_, Proof>,
    transactions: &[Transaction<V>],
) -> Result<Vec<ClientInput<V>>, BuildBlockError> {
    let vk_tree = db_locked.get_vk_tree();
    let mut client_inputs = Vec::new();
    let mut nullifier_tree = db_locked.get_global_nullifier_tree();
    // global_comm_roots is a vector with the roots of all transaction nullified commitments, one element per transaction
    let mut global_comm_roots: Vec<<P as Pairing>::ScalarField> = Vec::new();
    for (idx, transaction) in transactions.iter().enumerate() {
        let transaction_type = &transaction.circuit_type;
        let vk_info = prover
            .get_vk(transaction_type.clone())
            .ok_or(BuildBlockError::VksNotFound)?;
        let public_input: ClientPubInput<<V as Pairing>::ScalarField> = transaction.into();
        let low_nullifier_info = client_input::update_nullifier_tree::<V, 32>(
            &mut nullifier_tree,
            &public_input.nullifiers,
        )
        .map_err(|_| BuildBlockError::InvalidNullifier)?;
        let (vk, vk_idx) = vk_info;
        let mut client_input = ClientInput::<V>::new(
            transaction.proof.clone(),
            vk.clone(),
            public_input.commitments.len(),
            public_input.nullifiers.len(),
        );
        client_input
            .set_eph_pub_key(
                client_input::to_eph_key_array::<V>(public_input.ephemeral_public_key.clone())
                    .unwrap(),
            )
            .set_ciphertext(
                client_input::to_ciphertext_array::<V>(public_input.ciphertexts.clone()).unwrap(),
            )
            .set_nullifiers(&public_input.nullifiers)
            .set_commitments(&public_input.commitments)
            .set_commitment_tree_root(&public_input.commitment_root);
        client_input.vk_paths = vk_tree
            .membership_witness(vk_idx)
            .ok_or(BuildBlockError::VksNotFound)?
            .as_vec();
        client_input.vk_path_index = V::BaseField::from(vk_idx as u32);
        if let Some(info) = low_nullifier_info {
            global_comm_roots.push(field_switching(&public_input.commitment_root[0]));
            client_input
                .set_commitment_path_index(idx)
                .set_low_nullifier_info(&info);
        }
        client_inputs.push(client_input);
    }
    let global_root_tree: Tree<V::BaseField, 8> = Tree::from_leaves(global_comm_roots.clone());
    for client_input in &mut client_inputs {
        client_input.set_commitment_path(&global_root_tree);
    }

    Ok(client_inputs)
}
