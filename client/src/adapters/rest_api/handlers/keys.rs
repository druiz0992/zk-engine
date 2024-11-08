use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};

use axum::extract::State;
use axum::Json;
use curves::pallas::PallasConfig;

use crate::services::user_keys::UserKeys;

use crate::adapters::rest_api::structs::MnemonicInput;
use crate::usecase;

#[tracing::instrument(name = "Creating new keys", skip(db, mnemonic_str))]
pub async fn create_keys(
    State(db): State<AppState>,
    Json(mnemonic_str): Json<MnemonicInput>,
) -> Result<Json<UserKeys<PallasConfig>>, AppError> {
    let keys = usecase::create_keys::create_keys_process(db.state_db, mnemonic_str)
        .await
        .map_err(|_| AppError::TxError)?;
    Ok(Json(keys))
}
