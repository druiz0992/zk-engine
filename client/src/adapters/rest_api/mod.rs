pub mod structs;

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
        domain::{Fr, Preimage, PublicKey, Transaction},
        ports::{
            committable::Committable,
            keys::FullKey,
            storage::{KeyDB, PreimageDB, StoredPreimageInfo, TreeDB},
        },
        services::{
            derive_keys::{generate_keys, UserKeys},
            prover::in_memory_prover::InMemProver,
            storage::in_mem_storage::InMemStorage,
        },
        usecase::{mint::mint_tokens, transfer::transfer_tokens},
    };

    use super::structs::{MnemonicInput, PreimageResponse, TransferInput};

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

    // type WriteDatabase = Arc<Mutex<dyn PreimageDB<E = PallasConfig> + Send + Sync>>;
    type WriteDatabase = Arc<Mutex<InMemStorage<PallasConfig, curves::pallas::Fq>>>;
    pub async fn run_api(db_state: WriteDatabase) {
        dotenv().ok();
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/mint", post(create_mint))
            .route("/keys", post(create_keys))
            // .route("/keys", get(get_keys))
            .route("/transfer", post(create_transfer))
            // .route("/trees", get(get_trees))
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
            let _ = send.send(mint);
        });
        let transaction = recv.await.expect("Failed in rayon").unwrap();

        let mut db = db.lock().await;
        let preimage_key = mint_details
            .commitment_hash()
            .map_err(|_| AppError::TxError)?;
        let new_preimage = StoredPreimageInfo {
            preimage: mint_details,
            block_number: Some(0),
            leaf_index: Some(0),
            spent: false,
        };
        let _ = db
            .insert_preimage(preimage_key.0, new_preimage)
            .ok_or(AppError::TxError);

        // This is to simulate the mint being added to the tree
        db.add_block_leaves(vec![preimage_key.0], 0).unwrap();
        Ok(Json(transaction))
    }

    pub async fn create_keys(
        State(db): State<WriteDatabase>,
        Json(mnemonic_str): Json<MnemonicInput>,
    ) -> Result<Json<UserKeys<PallasConfig>>, AppError> {
        let mnemonic = Mnemonic::new(mnemonic_str.mnemonic, bip32::Language::English)
            .map_err(|_| AppError::TxError)?;
        let keys = generate_keys::<PallasConfig>(mnemonic).map_err(|_| AppError::TxError)?;
        db.lock()
            .await
            .insert_key(keys.public_key, keys)
            .ok_or(AppError::TxError)?;
        Ok(Json(keys))
    }

    pub async fn get_preimages(
        State(db): State<WriteDatabase>,
    ) -> Result<Json<Vec<PreimageResponse<PallasConfig>>>, AppError> {
        let db_locked = db.lock().await;
        let preimages: Vec<StoredPreimageInfo<PallasConfig>> = db_locked.get_all_preimages();
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

    // pub async fn get_trees(
    //     State(db): State<WriteDatabase>,
    // ) -> Result<Json<Vec<StoredPreimageInfo<PallasConfig>>>, AppError> {
    //     let db_locked = db.lock().await;
    //     let trees: Vec<StoredPreimageInfo<PallasConfig>> = db_locked.get_all_trees();
    //     Ok(Json(trees))
    // }
    //
    // pub async fn get_keys(
    //     State(db): State<WriteDatabase>,
    // ) -> Result<Json<Vec<User<M-Esc>>, AppError> {
    //     let db_locked = db.lock().await;
    //     let keys: Vec<FullKey<PallasConfig>> = db_locked.get_all_keys();
    //     Ok(Json(keys))
    // }

    pub async fn create_transfer(
        State(db): State<WriteDatabase>,
        Json(transfer_details): Json<TransferInput<PallasConfig>>,
    ) -> Result<Json<Transaction<VestaConfig>>, AppError> {
        let db_locked = db.lock().await;
        let stored_preimages: Vec<StoredPreimageInfo<PallasConfig>> = transfer_details
            .commitments_to_use
            .iter()
            .map(|key| db_locked.get_preimage(*key))
            .collect::<Option<_>>()
            .ok_or(AppError::TxError)?;
        let old_preimages: Vec<Preimage<PallasConfig>> =
            stored_preimages.iter().map(|x| x.preimage).collect();
        ark_std::println!(
            "Got commitment hash {}",
            old_preimages[0].commitment_hash().unwrap().0
        );
        let sibling_path_indices: Vec<Fr> = stored_preimages
            .iter()
            .map(|x| x.leaf_index.map(|x| crate::domain::EFq::from(x as u64)))
            .collect::<Option<_>>()
            .ok_or(AppError::TxError)?;
        let sibling_paths: Vec<Vec<Fr>> = stored_preimages
            .iter()
            .map(|x| db_locked.get_sibling_path(&x.block_number?, x.leaf_index?))
            .collect::<Option<Vec<_>>>()
            .ok_or(AppError::TxError)?;
        let commitment_roots: Vec<Fr> = stored_preimages
            .iter()
            .map(|x| db_locked.get_root(&x.block_number?))
            .collect::<Option<_>>()
            .ok_or(AppError::TxError)?;
        ark_std::println!("Got root {}", commitment_roots[0]);

        let root_key: Fr = db_locked
            .get_key(transfer_details.sender)
            .ok_or(AppError::TxError)?
            .get_private_key();

        let ephemeral_key = crate::domain::EFq::from(10u64);

        let recipients = PublicKey(transfer_details.recipient);
        let transaction =
            transfer_tokens::<PallasConfig, VestaConfig, _, InMemProver<VestaConfig>>(
                old_preimages,
                vec![transfer_details.transfer_amount],
                vec![recipients],
                sibling_paths,
                commitment_roots,
                sibling_path_indices,
                root_key,
                ephemeral_key,
            )
            .map_err(|_| AppError::TxError)?;
        Ok(Json(transaction))
    }
}
