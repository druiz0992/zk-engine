use axum::{extract::State, Json};
use curves::pallas::PallasConfig;

use crate::ports::committable::Committable;
use crate::ports::storage::PreimageDB;
use crate::ports::storage::StoredPreimageInfoVector;

use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};
use crate::adapters::rest_api::structs::PreimageResponse;

pub async fn get_preimages(
    State(db): State<AppState>,
) -> Result<Json<Vec<PreimageResponse<PallasConfig>>>, AppError> {
    let db_locked = db.state_db.lock().await;
    let preimages: StoredPreimageInfoVector<PallasConfig> = db_locked.get_all_preimages();
    let keys = preimages
        .iter()
        .map(|x| x.preimage.commitment_hash())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| AppError::TxError)?;
    let preimage_response = preimages
        .into_iter()
        .zip(keys)
        .map(|(x, y)| PreimageResponse {
            stored_preimage: x,
            commitment_hash: y.0,
        })
        .collect::<Vec<_>>();
    Ok(Json(preimage_response))
}
