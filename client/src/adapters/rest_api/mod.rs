pub mod structs;

pub mod rest_api_entry {
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::CurveGroup;
    use ark_poly::univariate::DensePolynomial;
    use common::serialize::{ark_de_std, ark_se_std, vec_ark_de, vec_ark_se};
    use common::structs::{Block, Commitment, Nullifier};

    use ark_ec::pairing::Pairing;
    use bip32::Mnemonic;
    use common::structs::Transaction;
    use jf_plonk::nightfall::ipa_structs::Proof;
    use serde::{Deserialize, Serialize};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use trees::MembershipPath;

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
        domain::{Fr, Preimage},
        ports::{
            committable::Committable,
            keys::FullKey,
            prover::Prover,
            storage::{KeyDB, PreimageDB, StoredPreimageInfo, StoredPreimageInfoVector, TreeDB},
        },
        services::{
            prover::in_memory_prover::InMemProver,
            storage::in_mem_storage::InMemStorage,
            user_keys::{generate_keys, UserKeys},
        },
        usecase::{mint::mint_tokens, transfer::transfer_tokens},
    };
    use common::keypair::PublicKey;
    use plonk_prover::client::circuits::{mint::MintCircuit, transfer::TransferCircuit};

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

    #[derive(Clone)]
    pub struct AppState {
        pub state_db: WriteDatabase,
        pub prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
    }
    pub async fn run_api(
        db_state: WriteDatabase,
        prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
    ) {
        dotenv().ok();
        let app_state = AppState {
            state_db: db_state,
            prover,
        };
        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/mint", post(create_mint))
            .route("/keys", post(create_keys))
            .route("/transfer", post(create_transfer))
            .route("/preimages", get(get_preimages))
            .route("/block", post(handle_block))
            .with_state(app_state);

        axum::Server::bind(&"0.0.0.0:3000".parse().unwrap())
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    #[derive(Serialize, Debug, Deserialize)]
    pub struct Tx<P>
    where
        P: Pairing,
        <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    {
        pub ct: Vec<Commitment<P::ScalarField>>,
        phantom: std::marker::PhantomData<P>,
        pub nullifiers: Vec<Nullifier<P::ScalarField>>,
        #[serde(serialize_with = "vec_ark_se", deserialize_with = "vec_ark_de")]
        pub ciphertexts: Vec<P::ScalarField>,
        #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
        pub proof: Proof<P>,
        #[serde(serialize_with = "ark_se_std", deserialize_with = "ark_de_std")]
        pub g_polys: DensePolynomial<P::ScalarField>,
    }

    async fn create_mint(
        State(db): State<AppState>,
        Json(mint_details): Json<Preimage<PallasConfig>>,
    ) -> Result<Json<Transaction<VestaConfig>>, AppError> {
        let prover = db.prover.lock().await;
        let circuit = MintCircuit::<1>::new();
        let pk = prover
            .get_pk(circuit.get_circuit_id())
            .ok_or(AppError::TxError)?;

        let transaction =
            mint_tokens::<PallasConfig, VestaConfig, _, InMemProver<PallasConfig, VestaConfig, _>>(
                circuit.as_circuit::<PallasConfig, VestaConfig, _>(),
                mint_details,
                pk,
            )
            .map_err(|_| AppError::TxError)?;

        let mut db = db.state_db.lock().await;
        let preimage_key = mint_details
            .commitment_hash()
            .map_err(|_| AppError::TxError)?;
        let new_preimage = StoredPreimageInfo {
            preimage: mint_details,
            nullifier: transaction.nullifiers[0].0,
            block_number: None,
            leaf_index: None,
            spent: false,
        };
        let _ = db
            .insert_preimage(preimage_key.0, new_preimage)
            .ok_or(AppError::TxError);

        // This is to simulate the mint being added to the tree
        // Replace with something better
        let client = reqwest::Client::new();
        // let cloned_tx = transaction.clone();
        // let tx = Tx {
        //     ct: transaction.commitments,
        //     nullifiers: transaction.nullifiers,
        //     ciphertexts: transaction.ciphertexts,
        //     proof: transaction.proof,
        //     g_polys: transaction.g_polys,
        //     phantom: std::marker::PhantomData,
        // };
        // let writer_str = serde_json::to_string(&tx).unwrap();
        // ark_std::println!("Got writer str {}", writer_str);
        // ark_std::println!(
        //     "unwrapped: {:?}",
        //     serde_json::from_str::<Tx<VestaConfig>>(&writer_str).unwrap()
        // );
        let res = client
            .post("http://127.0.0.1:4000/transactions")
            .json(&transaction)
            .send()
            .await;
        // ark_std::println!("Posted res");
        ark_std::println!("Got response {:?}", res);
        Ok(Json(transaction))
    }

    async fn handle_block(State(db): State<AppState>, Json(block): Json<Block<Fr>>) -> StatusCode {
        let mut db = db.state_db.lock().await;
        db.update_preimages(block.clone());

        db.add_block_leaves(block.commitments, block.block_number);
        StatusCode::CREATED
    }

    async fn create_keys(
        State(db): State<AppState>,
        Json(mnemonic_str): Json<MnemonicInput>,
    ) -> Result<Json<UserKeys<PallasConfig>>, AppError> {
        let mnemonic = Mnemonic::new(mnemonic_str.mnemonic, bip32::Language::English)
            .map_err(|_| AppError::TxError)?;
        let keys = generate_keys::<PallasConfig>(mnemonic).map_err(|_| AppError::TxError)?;
        db.state_db
            .lock()
            .await
            .insert_key(keys.public_key, keys)
            .ok_or(AppError::TxError)?;
        Ok(Json(keys))
    }

    async fn get_preimages(
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

    // pub async fn get_trees(
    //     State(db): State<WriteDatabase>,
    // ) -> Result<Json<StoredPreimageInfoVector<PallasConfig>>, AppError> {
    //     let db_locked = db.lock().await;
    //     let trees: StoredPreimageInfoVector<PallasConfig> = db_locked.get_all_trees();
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

    async fn create_transfer(
        State(db): State<AppState>,
        Json(transfer_details): Json<TransferInput<PallasConfig>>,
    ) -> Result<Json<Transaction<VestaConfig>>, AppError> {
        let db_locked = db.state_db.lock().await;
        let stored_preimages: StoredPreimageInfoVector<PallasConfig> = transfer_details
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
        let sibling_paths: Vec<MembershipPath<Fr>> = stored_preimages
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

        let prover = db.prover.lock().await;
        let circuit = TransferCircuit::<2, 2, 8>::new();
        let pk = prover
            .get_pk(circuit.get_circuit_id())
            .ok_or(AppError::TxError)?;

        let recipients = PublicKey(transfer_details.recipient);

        let transaction = transfer_tokens::<
            PallasConfig,
            VestaConfig,
            _,
            InMemProver<PallasConfig, VestaConfig, _>,
        >(
            circuit.as_circuit::<PallasConfig, VestaConfig, _>(),
            old_preimages,
            vec![transfer_details.transfer_amount],
            vec![recipients],
            sibling_paths,
            commitment_roots,
            sibling_path_indices,
            root_key,
            ephemeral_key,
            pk,
        )
        .map_err(|_| AppError::TxError)?;

        Ok(Json(transaction))
    }
}
