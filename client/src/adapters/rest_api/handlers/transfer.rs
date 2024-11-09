use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};
use crate::adapters::rest_api::structs::TransferInput;
use crate::usecase;
use axum::{extract::State, Json};
use common::structs::Transaction;
use curves::{pallas::PallasConfig, vesta::VestaConfig};

pub async fn create_transfer(
    State(db): State<AppState>,
    Json(transfer_details): Json<TransferInput<PallasConfig>>,
) -> Result<Json<Transaction<VestaConfig>>, AppError> {
    let transaction =
        usecase::transfer::transfer_process(db.state_db, db.prover, db.notifier, transfer_details)
            .await
            .map_err(|_| AppError::TxError)?;

    Ok(Json(transaction))
}
