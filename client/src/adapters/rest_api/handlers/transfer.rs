use common::structs::Transaction;
use trees::MembershipPath;

use axum::{extract::State, Json};
use curves::{pallas::PallasConfig, vesta::VestaConfig};

use crate::ports::committable::Committable;
use crate::ports::keys::FullKey;
use crate::ports::prover::Prover;
use crate::ports::storage::{KeyDB, PreimageDB, TreeDB};
use crate::{
    domain::{Fr, Preimage},
    ports::storage::StoredPreimageInfoVector,
    services::prover::in_memory_prover::InMemProver,
    usecase::transfer::transfer_tokens,
};
use common::keypair::PublicKey;
use plonk_prover::client::circuits::transfer::TransferCircuit;

use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};
use crate::adapters::rest_api::structs::TransferInput;

pub async fn create_transfer(
    State(db): State<AppState>,
    Json(transfer_details): Json<TransferInput<PallasConfig>>,
) -> Result<Json<Transaction<VestaConfig>>, AppError> {
    let db_locked = db.state_db.lock().await;
    let stored_preimages: StoredPreimageInfoVector<PallasConfig> = transfer_details
        .commitments_to_use
        .iter()
        .map(|key| db_locked.get_preimage(*key))
        .collect::<Option<_>>()
        .ok_or(AppError::TxError)?;
    let old_preimages: Vec<Preimage<PallasConfig>> =
        stored_preimages.iter().map(|x| x.preimage).collect();
    ark_std::println!(
        "Got commitment hash {}",
        old_preimages[0].commitment_hash().unwrap().0
    );
    let sibling_path_indices: Vec<Fr> = stored_preimages
        .iter()
        .map(|x| x.leaf_index.map(|x| crate::domain::EFq::from(x as u64)))
        .collect::<Option<_>>()
        .ok_or(AppError::TxError)?;
    let sibling_paths: Vec<MembershipPath<Fr>> = stored_preimages
        .iter()
        .map(|x| db_locked.get_sibling_path(&x.block_number?, x.leaf_index?))
        .collect::<Option<Vec<_>>>()
        .ok_or(AppError::TxError)?;
    let commitment_roots: Vec<Fr> = stored_preimages
        .iter()
        .map(|x| db_locked.get_root(&x.block_number?))
        .collect::<Option<_>>()
        .ok_or(AppError::TxError)?;
    ark_std::println!("Got root {}", commitment_roots[0]);

    let root_key: Fr = db_locked
        .get_key(transfer_details.sender)
        .ok_or(AppError::TxError)?
        .get_private_key();

    let ephemeral_key = crate::domain::EFq::from(10u64);

    let prover = db.prover.lock().await;
    let circuit = TransferCircuit::<2, 2, 8>::new();
    let pk = prover
        .get_pk(circuit.get_circuit_id())
        .ok_or(AppError::TxError)?;

    let recipients = PublicKey(transfer_details.recipient);
    let transaction =
        transfer_tokens::<PallasConfig, VestaConfig, _, InMemProver<PallasConfig, VestaConfig, _>>(
            circuit.as_circuit::<PallasConfig, VestaConfig, _>(),
            old_preimages,
            vec![transfer_details.transfer_amount],
            vec![recipients],
            sibling_paths,
            commitment_roots,
            sibling_path_indices,
            root_key,
            ephemeral_key,
            pk,
        )
        .map_err(|_| AppError::TxError)?;

    Ok(Json(transaction))
}
