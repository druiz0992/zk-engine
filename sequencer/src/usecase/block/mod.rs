use crate::domain::{RollupCommitKeys, RollupProvingKeys};
use crate::ports::prover::SequencerProver;
use crate::ports::storage::{BlockStorage, GlobalStateStorage, TransactionStorage};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use common::ports::notifier::Notifier;
use common::structs::CircuitType;
use common::structs::{Block, Transaction};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_utils::field_switching;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};
use tracing_log::log;
use trees::{AppendTree, IndexedMerkleTree, Tree};
use zk_macros::{client_bounds, prover_bounds};

mod build;
pub mod inputs;

pub enum BuildBlockError {
    VksNotFound,
    CommitKeysNotFound,
    BlockError(String),
    InvalidNullifierPath,
    InvalidNullifier,
    NotifierError,
    DispatcherNotFound,
}

#[client_bounds]
pub struct TransactionProcessor<P, V, VSW> {
    registry: HashMap<CircuitType, Box<dyn ClientPlonkCircuit<P, V, VSW>>>,
}

#[client_bounds]
impl<P, V, VSW> TransactionProcessor<P, V, VSW> {
    pub fn new() -> Self {
        TransactionProcessor {
            registry: HashMap::new(),
        }
    }

    pub fn register(
        &mut self,
        transaction_type: CircuitType,
        processor: Box<dyn ClientPlonkCircuit<P, V, VSW>>,
    ) {
        self.registry.insert(transaction_type, processor);
    }

    fn get_dispatcher(
        &self,
        transaction_type: &CircuitType,
    ) -> Option<&Box<dyn ClientPlonkCircuit<P, V, VSW>>> {
        self.registry.get(transaction_type)
    }
}

#[client_bounds]
impl<P, V, VSW> Default for TransactionProcessor<P, V, VSW> {
    fn default() -> Self {
        Self::new()
    }
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

fn get_commitments<V, Storage>(
    db_locked: &MutexGuard<'_, Storage>,
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
    let commitments = transactions
        .iter()
        .flat_map(|tx| tx.commitments.iter().map(|c| c.0))
        .collect::<Vec<_>>();

    let local_commitment_tree: Tree<V::ScalarField, 8> = Tree::from_leaves(commitments.clone());
    db_locked
        .get_global_commitment_tree()
        .append_leaf(field_switching(&local_commitment_tree.root()));

    (commitments, local_commitment_tree.root())
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
    processor: Arc<Mutex<TransactionProcessor<P, V, VSW>>>,
) -> Result<Block<V::ScalarField>, BuildBlockError> {
    log::debug!("Preparing block");
    let prover = prover.lock().await;
    let db_locked = db.lock().await;
    let processor = processor.lock().await;

    let (proving_keys, commit_keys) = get_keys(&prover)?;
    let transactions = db_locked.get_all_transactions();
    let g_polys = get_g_polys(&transactions);
    let (commitments, commitments_root) = get_commitments(&db_locked, &transactions);
    let nullifiers = vec![];

    let inputs = inputs::build_client_inputs::<P, V, SW, VSW, Storage, Proof>(
        db_locked,
        prover,
        processor,
        transactions,
    )
    .await?;

    let block = build::build_block::<P, V, SW, VSW, Storage, Proof>(
        db.clone(),
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

    let notifier = notifier.lock().await;
    notifier
        .send_info(block.clone())
        .await
        .map_err(|_| BuildBlockError::NotifierError)?;
    // ark_std::println!("Posted res");

    Ok(block)
}
