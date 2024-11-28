use crate::adapters::rest_api::sequencer_api::SequencerState;
use crate::ports::storage::TransactionStorage;
use axum::{extract::State, http::StatusCode};
use axum_serde::Cbor;
use common::structs::Transaction;
use curves::vesta::VestaConfig;

#[tracing::instrument(name = "Received Transaction", skip(db, tx))]
pub async fn handle_tx(
    State(db): State<SequencerState>,
    Cbor(tx): Cbor<Transaction<VestaConfig>>,
) -> Result<StatusCode, StatusCode> {
    let mut db = db.state_db.lock().await;
    // Assume tx is valid here
    db.insert_transaction(tx);
    Ok(StatusCode::CREATED)
}

#[tracing::instrument(name = "Requested Transaction", skip(db))]
pub async fn get_tx(
    State(db): State<SequencerState>,
) -> Result<Cbor<Vec<Transaction<VestaConfig>>>, StatusCode> {
    let db = db.state_db.lock().await;
    Ok(Cbor(db.get_all_transactions()))
}
