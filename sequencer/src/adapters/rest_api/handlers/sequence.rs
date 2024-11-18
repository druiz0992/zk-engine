use crate::usecase;
use crate::{adapters::rest_api::sequencer_api::SequencerState, usecase::block::BuildBlockError};
use axum::{extract::State, http::StatusCode, Json};
use common::structs::Block;

impl From<BuildBlockError> for StatusCode {
    fn from(value: BuildBlockError) -> Self {
        match value {
            BuildBlockError::BlockError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[tracing::instrument(name = "New Block Make Request", skip(db))]
pub async fn make_block(
    State(db): State<SequencerState>,
) -> Result<Json<Block<curves::vesta::Fr>>, StatusCode> {
    let block = usecase::block::build_block_process(db.state_db, db.prover, db.notifier)
        .await
        .map_err(StatusCode::from)?;

    Ok(Json(block))
}
