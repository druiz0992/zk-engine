use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};

use axum::extract::State;
use axum::Json;
use curves::pallas::PallasConfig;

use crate::{ports::storage::KeyDB, services::user_keys::UserKeys};

use crate::adapters::rest_api::structs::MnemonicInput;
use crate::usecase::create_keys::create_user_keys_from_mnemonic;

#[tracing::instrument(name = "Creating new keys", skip(db, mnemonic_str))]
pub async fn create_keys(
    State(db): State<AppState>,
    Json(mnemonic_str): Json<MnemonicInput>,
) -> Result<Json<UserKeys<PallasConfig>>, AppError> {
    let keys = create_user_keys_from_mnemonic::<PallasConfig>(mnemonic_str)
        .map_err(|_| AppError::TxError)?;

    db.state_db
        .lock()
        .await
        .insert_key(keys.public_key, keys)
        .ok_or(AppError::TxError)?;
    Ok(Json(keys))
}
