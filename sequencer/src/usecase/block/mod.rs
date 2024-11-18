use crate::ports::prover::SequencerProver;
use crate::ports::storage::{GlobalStateStorage, TransactionStorage};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::ports::notifier::Notifier;
use common::structs::Block;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::circuits::{mint, transfer};
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use std::sync::Arc;
use tokio::sync::Mutex;
use trees::{IndexedMerkleTree, Tree};

mod build;
mod inputs;

pub enum BuildBlockError {
    VksNotFound,
    CommitKeysNotFound,
    BlockError(String),
    InvalidNullifierPath,
    InvalidNullifier,
    NotifierError,
}
pub async fn build_block_process<
    P,
    V,
    SW,
    VSW,
    Proof: SequencerProver<V, VSW, P, SW>,
    Storage: TransactionStorage<V>
        + GlobalStateStorage<
            CommitmentTree = Tree<V::BaseField, 8>,
            VkTree = Tree<V::BaseField, 2>,
            NullifierTree = IndexedMerkleTree<V::BaseField, 32>,
        >,
    Comms: Notifier<Info = Block<V::ScalarField>>,
>(
    db: Arc<Mutex<Storage>>,
    prover: Arc<Mutex<Proof>>,
    notifier: Arc<Mutex<Comms>>,
) -> Result<Block<V::ScalarField>, BuildBlockError>
where
    V: Pairing<
        G1Affine = Affine<VSW>,
        G1 = Projective<VSW>,
        ScalarField = <P as CurveConfig>::BaseField,
    >,
    <V as Pairing>::BaseField: PrimeField
        + PoseidonParams<Field = <P as Pairing>::ScalarField>
        + RescueParameter
        + SWToTEConParam,
    <V as Pairing>::ScalarField: PrimeField
        + PoseidonParams<Field = <P as Pairing>::BaseField>
        + RescueParameter
        + SWToTEConParam,
    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,

    P: Pairing<G1Affine = Affine<SW>, G1 = Projective<SW>>
        + SWCurveConfig
        + Pairing<BaseField = <V as Pairing>::ScalarField, ScalarField = <V as Pairing>::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,

    SW: SWCurveConfig<
        BaseField = <V as Pairing>::ScalarField,
        ScalarField = <V as Pairing>::BaseField,
    >,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
{
    let prover = prover.lock().await;
    ark_std::println!("Get the mofo vks");
    let vks = [
        mint::MintCircuit::<1>::new()
            .as_circuit::<P, V, _>()
            .get_circuit_id(),
        transfer::TransferCircuit::<2, 2, 8>::new()
            .as_circuit::<P, V, _>()
            .get_circuit_id(),
    ]
    .into_iter()
    .map(|x| prover.get_vk(x))
    .collect::<Option<Vec<_>>>()
    .ok_or(BuildBlockError::VksNotFound)?;
    let proving_keys = prover.get_pks();

    let commit_keys = prover
        .get_cks()
        .ok_or(BuildBlockError::CommitKeysNotFound)?;
    ark_std::println!("Preparing block");

    let state_db = db.lock().await;
    let transactions = state_db.get_all_transactions();
    let nullifiers = transactions
        .iter()
        .flat_map(|tx| tx.nullifiers.iter().map(|n| n.0))
        .collect::<Vec<_>>();

    let (inputs, commitments, commitments_root) =
        inputs::build_client_inputs::<P, V, SW, VSW, Storage>(db.clone(), transactions, vks)
            .await?;

    let block = build::build_block::<P, V, SW, VSW, Storage, Proof>(
        db.clone(),
        inputs,
        nullifiers,
        commitments,
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
