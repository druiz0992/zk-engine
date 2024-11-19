use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use common::{crypto::poseidon::constants::PoseidonParams, structs::Transaction};
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_utils::field_switching;
use plonk_prover::rollup::circuits::client_input::ClientInput;
use trees::{
    membership_tree::{MembershipTree, Tree},
    non_membership_tree::{IndexedMerkleTree, IndexedNode, NonMembershipTree},
    tree::AppendTree,
    MembershipPath,
};
use zk_macros::sequencer_circuit;

use crate::ports::storage::GlobalStateStorage;
use std::sync::Arc;
use tokio::sync::Mutex;

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

async fn get_vk_paths_from_indices<V, Storage>(
    db: Arc<Mutex<Storage>>,
    vks_indices: &[usize],
) -> Result<Vec<MembershipPath<V::BaseField>>, &'static str>
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    ark_std::println!("vk_paths");
    let db_locked = db.lock().await;
    let vk_paths: Vec<MembershipPath<V::BaseField>> = vks_indices
        .iter()
        .map(|vk| db_locked.get_vk_tree().membership_witness(*vk))
        .collect::<Option<Vec<MembershipPath<_>>>>()
        .ok_or("Invalid vk index")?;

    Ok(vk_paths)
}

async fn get_low_nullifier_path<V, Storage>(
    db: Arc<Mutex<Storage>>,
    transactions: &[Transaction<V>],
) -> Result<Vec<MembershipPath<V::BaseField>>, &'static str>
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    ark_std::println!("low nullifier path");
    let db_locked = db.lock().await;
    let low_nullifier_path: Vec<MembershipPath<V::BaseField>> = transactions
        .iter()
        .flat_map(|tx| {
            tx.nullifiers
                .iter()
                .filter(|nullifier| !nullifier.0.is_zero())
                .map(|nullifier| {
                    let nullifier_fr = field_switching(&nullifier.0);
                    db_locked
                        .get_global_nullifier_tree()
                        .non_membership_witness(nullifier_fr)
                        .ok_or("Invalid nullifier")
                })
                .collect::<Vec<_>>()
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(low_nullifier_path)
}

async fn get_low_nullifier<V, Storage>(
    db: Arc<Mutex<Storage>>,
    transactions: &[Transaction<V>],
) -> Result<Vec<IndexedNode<V::BaseField>>, &'static str>
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    let db_locked = db.lock().await;
    ark_std::println!("low nulliifer");
    let low_nullifier: Vec<IndexedNode<V::BaseField>> = transactions
        .iter()
        .flat_map(|tx| {
            tx.nullifiers
                .iter()
                .filter(|nullifier| !nullifier.0.is_zero())
                .map(|n| {
                    let nullifier_fr = field_switching(&n.0);
                    db_locked
                        .get_global_nullifier_tree()
                        .find_predecessor(nullifier_fr)
                        .node
                })
        })
        .collect::<Vec<_>>();

    Ok(low_nullifier)
}

async fn append_commitments<V, Storage>(
    db: Arc<Mutex<Storage>>,
    transactions: &[Transaction<V>],
) -> (Vec<V::ScalarField>, V::ScalarField)
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    let db_locked = db.lock().await;
    let commitments = transactions
        .iter()
        .flat_map(|tx| tx.commitments.iter().map(|c| c.0))
        .collect::<Vec<_>>();

    ark_std::println!("commitment tree");
    let local_commitment_tree: Tree<V::ScalarField, 8> = Tree::from_leaves(commitments.clone());
    db_locked
        .get_global_commitment_tree()
        .append_leaf(field_switching(&local_commitment_tree.root()));
    ark_std::println!("commitment tree root: {:?}", local_commitment_tree.root());

    (commitments, local_commitment_tree.root())
}

#[sequencer_circuit]
pub async fn build_client_inputs<P, V, SW, VSW, Storage>(
    db: Arc<Mutex<Storage>>,
    transactions: Vec<Transaction<V>>,
    vks: Vec<VerifyingKey<V>>,
) -> Result<(Vec<ClientInput<V, 8>>, Vec<V::ScalarField>, V::ScalarField), BuildBlockError>
where
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 2>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    let vks_indices = vec![0, 1];
    let vk_paths = get_vk_paths_from_indices::<V, Storage>(db.clone(), &vks_indices)
        .await
        .map_err(|_| BuildBlockError::VksNotFound)?;

    let low_nullifier_path = get_low_nullifier_path(db.clone(), &transactions)
        .await
        .map_err(|_| BuildBlockError::InvalidNullifierPath)?;

    let low_nullifier = get_low_nullifier(db.clone(), &transactions)
        .await
        .map_err(|_| BuildBlockError::InvalidNullifier)?;

    let (commitments, commitments_root) = append_commitments(db.clone(), &transactions).await;

    let client_inputs: Vec<_> = transactions
        .into_iter()
        .enumerate()
        .map(|(i, t)| ClientInput::<V, 8> {
            proof: t.proof,
            nullifiers: t.nullifiers.iter().map(|n| n.0).collect::<Vec<_>>(),
            commitments: t.commitments.iter().map(|c| c.0).collect::<Vec<_>>(),
            commitment_tree_root: vec![V::ScalarField::from(0u8); 1],
            path_comm_tree_root_to_global_tree_root: vec![[V::BaseField::from(0u8); 8]],
            //path_comm_tree_index: [F::zero()],
            path_comm_tree_index: vec![V::BaseField::from(0u32)],
            low_nullifier: low_nullifier.clone(),
            low_nullifier_indices: vec![V::BaseField::zero()],
            low_nullifier_mem_path: low_nullifier_path
                .clone()
                .into_iter()
                .map(|p| p.try_into().unwrap_or([V::BaseField::zero(); 32]))
                .collect::<Vec<_>>(),
            vk_paths: vk_paths[i].clone().as_vec(),
            vk_path_index: V::BaseField::from(vks_indices[i] as u64),
            vk: vks[i].clone(),
            ciphertext: [V::ScalarField::from(0u8); 3],
            eph_pub_key: [V::BaseField::from(0u8); 2],
            swap_field: t.swap_field,
        })
        .collect::<Vec<_>>();

    Ok((client_inputs, commitments, commitments_root))
}