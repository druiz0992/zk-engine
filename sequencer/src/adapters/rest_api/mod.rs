pub mod sequencer_api {
    use std::sync::Arc;

    use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
    use ark_poly::univariate::DensePolynomial;
    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use common::structs::{Block, Transaction};
    use common::structs::{Commitment, Nullifier};
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use dotenvy::dotenv;
    use jf_plonk::nightfall::ipa_structs::Proof;
    use serde::Deserialize;
    use tokio::sync::Mutex;

    use plonk_prover::client::circuits::mint::MintCircuit;
    use plonk_prover::client::circuits::transfer::TransferCircuit;

    use crate::{
        ports::{prover::SequencerProver, storage::TransactionStorage},
        services::{
            prover::in_mem_sequencer_prover::InMemProver,
            storage::in_mem_sequencer_storage::InMemStorage,
        },
        usecase::build_block::build_block,
    };
    use common::serialize::{ark_de_std, vec_ark_de};

    type SequencerDB = Arc<Mutex<InMemStorage>>;
    type SequenceProve =
        Arc<Mutex<InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig>>>;
    #[derive(Clone)]
    pub struct SequencerState {
        pub state_db: SequencerDB,
        pub prover: SequenceProve,
    }
    pub async fn run_sequencer_api(sequencer_db: SequencerDB, sequencer_prover: SequenceProve) {
        dotenv().ok();
        let state = SequencerState {
            state_db: sequencer_db,
            prover: sequencer_prover,
        };

        let app = Router::new()
            .route("/health", get(|| async { StatusCode::OK }))
            .route("/transactions", post(handle_tx))
            .route("/transactions", get(get_tx))
            .route("/sequence", post(make_block))
            .with_state(state);

        axum::Server::bind(&"0.0.0.0:4000".parse().unwrap())
            .serve(app.into_make_service())
            .await
            .unwrap();
    }

    #[derive(Deserialize, Debug)]
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

    pub async fn handle_tx(
        State(db): State<SequencerState>,
        Json(tx): Json<Transaction<VestaConfig>>,
    ) -> Result<StatusCode, StatusCode> {
        ark_std::println!("RECEIVED TX");
        // ark_std::println!("TX: {:?}", tx);
        let mut db = db.state_db.lock().await;
        // Assume tx is valid here
        db.insert_transaction(tx);
        Ok(StatusCode::CREATED)
    }
    pub async fn get_tx(
        State(db): State<SequencerState>,
    ) -> Result<Json<Vec<Transaction<VestaConfig>>>, StatusCode> {
        let db = db.state_db.lock().await;
        Ok(Json(db.get_all_transactions()))
    }

    pub async fn make_block(
        State(db): State<SequencerState>,
    ) -> Result<Json<Block<curves::vesta::Fr>>, StatusCode> {
        let state_db = db.state_db.lock().await;
        let transactions = state_db.get_all_transactions();
        let prover = db.prover.lock().await;
        ark_std::println!("Get the mofo vks");
        let vks = [
            MintCircuit::<1>::new()
                .as_circuit::<PallasConfig, VestaConfig, _>()
                .get_circuit_id(),
            TransferCircuit::<2, 2, 8>::new()
                .as_circuit::<PallasConfig, VestaConfig, _>()
                .get_circuit_id(),
        ]
        .into_iter()
        .map(|x| prover.get_vk(x))
        .collect::<Option<Vec<_>>>()
        .ok_or(StatusCode::BAD_REQUEST)?;

        let commit_keys = prover.get_cks().ok_or(StatusCode::BAD_REQUEST)?;
        let proving_keys = prover.get_pks();
        ark_std::println!("Preparing block");

        let block = build_block::<
            PallasConfig,
            VestaConfig,
            InMemStorage,
            InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig>,
            _,
            VestaConfig,
        >(
            transactions,
            vks,
            vec![0, 1],
            (*state_db).clone(),
            commit_keys,
            proving_keys,
        )
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        let client = reqwest::Client::new();
        let res = client
            .post("http://127.0.0.1:3000/block")
            .json(&block)
            .send()
            .await;
        // ark_std::println!("Posted res");
        ark_std::println!("Got response {:?}", res);

        Ok(Json(block))
    }
}
