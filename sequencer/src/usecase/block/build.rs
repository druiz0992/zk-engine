use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::{crypto::poseidon::constants::PoseidonParams, structs::Block};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::rollup::circuits::client_input::ClientInput;
use trees::{membership_tree::Tree, non_membership_tree::IndexedMerkleTree, tree::AppendTree};
use zk_macros::sequencer_bounds;

use crate::{
    domain::{RollupCommitKeys, RollupProvingKeys},
    ports::{
        prover::SequencerProver,
        storage::{BlockStorage, GlobalStateStorage},
    },
};
use tokio::sync::MutexGuard;
use tracing_log::log;

use super::BuildBlockError;

// pub struct ClientInput<P, V, const C: usize, const N: usize>
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

#[sequencer_bounds]
pub async fn build_block<P, V, SW, VSW, Storage, Prover>(
    db_locked: &mut MutexGuard<'_, Storage>,
    client_inputs: Vec<ClientInput<V>>,
    nullifiers: Vec<V::ScalarField>,
    commitments: Vec<V::ScalarField>,
    g_polys: Vec<DensePolynomial<V::ScalarField>>,
    local_commitment_root: V::ScalarField,
    commit_keys: RollupCommitKeys<V, VSW, P, SW>,
    proving_keys: Option<RollupProvingKeys<V, VSW, P, SW>>,
) -> Result<Block<V::ScalarField>, BuildBlockError>
where
    Storage: GlobalStateStorage<
            CommitmentTree = Tree<V::BaseField, 8>,
            VkTree = Tree<V::BaseField, 8>,
            NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
        > + BlockStorage<V::ScalarField>,
    Prover: SequencerProver<V, VSW, P, SW>,
{
    // client_inputs: [ClientInput<V, 1, 1>; 2],
    // global_vk_root: P::ScalarField,
    // global_nullifier_root: P::ScalarField,
    // global_nullifier_leaf_count: P::ScalarField,
    // global_commitment_root: P::ScalarField,
    // g_polys: [DensePolynomial<P::BaseField>; 2],
    // commit_key: CommitKey<V>,
    let vk_tree_root = db_locked.get_vk_tree().root();
    // Global nullifier tree, updated with the latest transactions to be processed in this block
    let global_nullifier_tree = db_locked.get_global_nullifier_tree();
    let global_nullifier_tree_root = global_nullifier_tree.root();
    let global_nullifier_tree_leaf_count = V::BaseField::from(global_nullifier_tree.leaf_count());
    // Global commitment tree updated with root formed with all commitments processed in this block
    let global_commitment_tree_root = db_locked.get_global_commitment_tree().root();
    let block_count = db_locked.get_block_count();

    log::debug!("build_block");
    let block =
        tokio::task::spawn_blocking(move || -> Result<Block<V::ScalarField>, BuildBlockError> {
            Prover::rollup_proof(
                client_inputs,
                vk_tree_root,
                global_nullifier_tree_root,
                global_nullifier_tree_leaf_count,
                global_commitment_tree_root,
                g_polys,
                commit_keys,
                proving_keys,
            )
            .map_err(|e| BuildBlockError::BlockError(e.to_string()))?;

            Ok(Block {
                block_number: block_count,
                commitments,
                nullifiers,
                commitment_root: local_commitment_root,
            })
        })
        .await;

    let block = match block {
        Ok(inner_result) => inner_result?,
        Err(e) => {
            return Err(BuildBlockError::BlockError(format!(
                "Task panicked: {:?}",
                e
            )));
        }
    };

    db_locked.insert_block(block.clone());

    Ok(block)

    // Given transaction list, produce a block
}
