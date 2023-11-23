mod structs;

pub mod rest_api_entry {

    use bip32::Mnemonic;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    use axum::{
        extract::State,
        http::StatusCode,
        response::IntoResponse,
        routing::{get, post},
        Json, Router,
    };
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use dotenvy::dotenv;
    use serde_json::json;

    use crate::{
        domain::{Preimage, Transaction},
        ports::{committable::Committable, storage::PreimageDB},
        services::{
            derive_keys::{generate_keys, UserKeys},
            prover::in_memory_prover::InMemProver,
        },
        usecase::{
            mint::{self, mint_tokens},
            transfer::transfer_tokens,
        },
    };

    use super::structs::{MnemonicInput, TransferInput};

    pub enum AppError {
        TxError,
    }
    impl IntoResponse for AppError {
        fn into_response(self) -> axum::response::Response {
            let (status, error_msg) = match self {
                AppError::TxError => (StatusCode::INTERNAL_SERVER_ERROR, "Internal Error"),
            };
            let body = Json(json!({
                "error": error_msg,
            }));
            (status, body).into_response()
        }
    }

    type WriteDatabase = Arc<Mutex<dyn PreimageDB<E = PallasConfig> + Send + Sync>>;
    pub async fn run_api(db_state: WriteDatabase) {
        dotenv().ok();
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/mint", post(create_mint))
            .route("/keys", post(create_keys))
            .route("/transfer", post(create_transfer))
            .route("/preimages", get(get_preimages))
            .with_state(db_state);

        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    pub async fn create_mint(
        State(db): State<WriteDatabase>,
        Json(mint_details): Json<Preimage<PallasConfig>>,
    ) -> Result<Json<Transaction<VestaConfig>>, AppError> {
        let (send, recv) = tokio::sync::oneshot::channel();
        rayon::spawn(move || {
            let mint = mint_tokens::<PallasConfig, VestaConfig, _, InMemProver<VestaConfig>>(
                vec![mint_details.value],
                vec![mint_details.token_id],
                vec![mint_details.salt],
                vec![mint_details.public_key],
            );
            send.send(mint);
        });
        let transaction = recv.await.expect("Failed in rayon").unwrap();

        let mut db = db.lock().await;
        let preimage_key = mint_details
            .commitment_hash()
            .map_err(|_| AppError::TxError)?;
        db.insert_preimage(preimage_key.0, mint_details);
        Ok(Json(transaction))
    }

    pub async fn create_keys(
        Json(mnemonic_str): Json<MnemonicInput>,
    ) -> Result<Json<UserKeys<PallasConfig>>, AppError> {
        let mnemonic = Mnemonic::new(mnemonic_str.mnemonic, bip32::Language::English)
            .map_err(|_| AppError::TxError)?;
        let keys = generate_keys::<PallasConfig>(mnemonic).map_err(|_| AppError::TxError)?;
        Ok(Json(keys))
    }

    pub async fn get_preimages(
        State(db): State<WriteDatabase>,
    ) -> Result<Json<Vec<Preimage<PallasConfig>>>, AppError> {
        let db_locked = db.lock().await;
        let preimages = db_locked.get_all_preimages();
        Ok(Json(preimages))
    }

    pub async fn create_transfer(
        State(db): State<WriteDatabase>,
        Json(transfer_details): Json<TransferInput<PallasConfig>>,
    ) -> Result<Json<Transaction<VestaConfig>>, AppError> {
        let db_locked = db.lock().await;
        let old_preimages = transfer_details
            .commitments_to_use
            .iter()
            .map(|key| db_locked.get_preimage(key).ok_or(AppError::TxError))
            .collect()?;
        transfer_tokens(
            old_preimages,
            new_token_values,
            recipients,
            sibling_paths,
            commitment_roots,
            membership_path_index,
            root_key,
            ephemeral_key,
        )
    }
}
