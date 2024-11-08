use common::structs::Transaction;

use axum::{extract::State, Json};
use curves::{pallas::PallasConfig, vesta::VestaConfig};

use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};
use crate::{domain::Preimage, usecase};

#[tracing::instrument(name = "Creating new mint transaction", skip(db, mint_details))]
pub async fn create_mint(
    State(db): State<AppState>,
    Json(mint_details): Json<Vec<Preimage<PallasConfig>>>,
) -> Result<Json<Transaction<VestaConfig>>, AppError> {
    let transaction =
        usecase::mint::mint_process(db.state_db, db.prover, db.notifier, mint_details)
            .await
            .map_err(|_| AppError::TxError)?;

    Ok(Json(transaction))
}
