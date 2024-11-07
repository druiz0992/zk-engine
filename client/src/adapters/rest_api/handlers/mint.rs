use common::structs::Transaction;

use axum::{extract::State, Json};
use curves::{pallas::PallasConfig, vesta::VestaConfig};

use crate::adapters::rest_api::rest_api_entry::{AppError, AppState};
use crate::ports::{prover::Prover, storage::PreimageDB};
use crate::{
    domain::Preimage,
    ports::{committable::Committable, storage::StoredPreimageInfo},
    services::prover::in_memory_prover::InMemProver,
    usecase::mint::mint_tokens,
};
use plonk_prover::client::circuits::mint::MintCircuit;

pub async fn create_mint(
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
