use crate::domain::{RollupCommitKeys, RollupProvingKeys};
use crate::ports::prover::SequencerProver;
use crate::ports::storage::{BlockStorage, GlobalStateStorage, TransactionStorage};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use common::ports::notifier::Notifier;
use common::structs::{Block, Transaction};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_utils::field_switching;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tracing_log::log;
use trees::{AppendTree, IndexedMerkleTree, Tree};
use zk_macros::prover_bounds;

mod build;
pub mod inputs;

#[derive(Debug)]
pub enum BuildBlockError {
    VksNotFound,
    CommitKeysNotFound,
    BlockError(String),
    InvalidNullifierPath,
    InvalidNullifier,
    NotifierError,
    DispatcherNotFound,
}

#[prover_bounds]
fn get_keys<P, V, SW, VSW, Proof>(
    prover: &MutexGuard<'_, Proof>,
) -> Result<
    (
        Option<RollupProvingKeys<V, VSW, P, SW>>,
        RollupCommitKeys<V, VSW, P, SW>,
    ),
    BuildBlockError,
>
where
    Proof: SequencerProver<V, VSW, P, SW>,
{
    let proving_keys = prover.get_pks();
    let commit_keys = prover
        .get_cks()
        .ok_or(BuildBlockError::CommitKeysNotFound)?;
    Ok((proving_keys, commit_keys))
}

fn get_g_polys<V>(transactions: &[Transaction<V>]) -> Vec<DensePolynomial<V::ScalarField>>
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    transactions
        .iter()
        .map(|tx| tx.g_polys.clone())
        .collect::<Vec<_>>()
}

fn get_commitments_and_update_tree<V, Storage>(
    db_locked: &mut MutexGuard<'_, Storage>,
    transactions: &[Transaction<V>],
) -> (Vec<V::ScalarField>, V::ScalarField)
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
    Storage: GlobalStateStorage<
        CommitmentTree = Tree<V::BaseField, 8>,
        VkTree = Tree<V::BaseField, 8>,
        NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
    >,
{
    let mut global_commitment_tree = db_locked.get_global_commitment_tree();
    let commitments = transactions
        .iter()
        .flat_map(|tx| {
            let tx_commitments: Vec<_> = tx
                .commitments
                .iter()
                .map(|c| c.0)
                .filter(|&c| c != V::ScalarField::zero())
                .collect();
            let local_commitment_tree: Tree<V::ScalarField, 8> =
                Tree::from_leaves(tx_commitments.clone());
            let local_commitment_tree_root = local_commitment_tree.root();
            global_commitment_tree.append_leaf(field_switching(&local_commitment_tree_root));
            tx_commitments
        })
        .collect::<Vec<_>>();

    let local_commitment_tree: Tree<V::ScalarField, 8> = Tree::from_leaves(commitments.clone());
    let local_commitment_tree_root = local_commitment_tree.root();
    db_locked.store_global_commitment_tree(global_commitment_tree);

    (commitments, local_commitment_tree_root)
}

fn get_nullifiers<V>(transactions: &[Transaction<V>]) -> Vec<V::ScalarField>
where
    V: Pairing,
    <V as Pairing>::BaseField: PoseidonParams<Field = V::BaseField>,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    <V as Pairing>::ScalarField: PoseidonParams<Field = V::ScalarField>,
{
    transactions
        .iter()
        .flat_map(|tx| {
            tx.nullifiers
                .iter()
                .map(|n| n.0)
                .filter(|&n| n != V::ScalarField::zero())
        })
        .collect::<Vec<_>>()
}

#[prover_bounds]
pub async fn build_block_process<
    P,
    V,
    SW,
    VSW,
    Proof: SequencerProver<V, VSW, P, SW>,
    Storage: TransactionStorage<V>
        + GlobalStateStorage<
            CommitmentTree = Tree<V::BaseField, 8>,
            VkTree = Tree<V::BaseField, 8>,
            NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
        > + BlockStorage<V::ScalarField>,
    Comms: Notifier<Info = Block<V::ScalarField>>,
>(
    db: Arc<Mutex<Storage>>,
    prover: Arc<Mutex<Proof>>,
    notifier: Arc<Mutex<Comms>>,
) -> Result<Block<V::ScalarField>, BuildBlockError> {
    log::debug!("Preparing block");
    let prover = prover.lock().await;
    let mut db_locked = db.lock().await;

    let (proving_keys, commit_keys) = get_keys(&prover)?;
    let transactions = db_locked.get_mempool_transactions();
    let g_polys = get_g_polys(&transactions);
    let nullifiers = get_nullifiers(&transactions);

    let inputs =
        inputs::build_client_inputs_and_update_nullifier_tree::<P, V, SW, VSW, Storage, Proof>(
            &db_locked,
            &prover,
            &transactions,
        )
        .await?;
    // root stores the root of the tree formed by all commitments in all transactions submitted
    let (commitments, commitments_root) =
        get_commitments_and_update_tree(&mut db_locked, &transactions);

    let block = build::build_block::<P, V, SW, VSW, Storage, Proof>(
        &mut db_locked,
        inputs,
        nullifiers,
        commitments,
        g_polys,
        commitments_root,
        commit_keys,
        proving_keys,
    )
    .await
    .map_err(|_| BuildBlockError::BlockError("Unable to build block".to_string()))?;

    db_locked.flush_mempool_transactions();

    let notifier = notifier.lock().await;
    notifier
        .send_info(block.clone())
        .await
        .map_err(|_| BuildBlockError::NotifierError)?;

    Ok(block)
}
