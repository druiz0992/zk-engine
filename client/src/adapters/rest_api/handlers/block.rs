use common::structs::Block;

use axum::{extract::State, http::StatusCode, Json};

use crate::adapters::rest_api::rest_api_entry::AppState;
use crate::domain::Fr;
use crate::ports::storage::{PreimageDB, TreeDB};

pub async fn handle_block(State(db): State<AppState>, Json(block): Json<Block<Fr>>) -> StatusCode {
    let mut db = db.state_db.lock().await;
    db.update_preimages(block.clone());

    db.add_block_leaves(block.commitments, block.block_number);
    StatusCode::CREATED
}
