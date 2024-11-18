use crate::adapters::rest_api::sequencer_api::SequencerState;
use crate::ports::storage::TransactionStorage;
use axum::{extract::State, http::StatusCode, Json};
use common::structs::Transaction;
use curves::vesta::VestaConfig;

#[tracing::instrument(name = "Received Transaction", skip(db))]
pub async fn handle_tx(
    State(db): State<SequencerState>,
    Json(tx): Json<Transaction<VestaConfig>>,
) -> Result<StatusCode, StatusCode> {
    let mut db = db.state_db.lock().await;
    // Assume tx is valid here
    db.insert_transaction(tx);
    Ok(StatusCode::CREATED)
}

#[tracing::instrument(name = "Requested Transaction", skip(db))]
pub async fn get_tx(
    State(db): State<SequencerState>,
) -> Result<Json<Vec<Transaction<VestaConfig>>>, StatusCode> {
    let db = db.state_db.lock().await;
    Ok(Json(db.get_all_transactions()))
}
