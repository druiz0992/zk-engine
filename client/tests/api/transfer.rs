use crate::helpers::spawn_app;
use client::ports::storage::PreimageDB;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn transfer_endpoint_returns_200_with_correct_input() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_response = app.post_mint_request(vec![["1", "1"]]).await;
    assert!(mint_response.status().is_success());

    let db_locked = app.db.lock().await;
    let _a = db_locked.get_all_preimages();
}
