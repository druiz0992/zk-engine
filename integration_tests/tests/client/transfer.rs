use integration_tests::client::{mint::MintParams, test_app::spawn_app};
//use client::ports::storage::PreimageDB;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn transfer_endpoint_returns_200_with_correct_input() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_response = app.post_mint_request(mint_params).await;
    assert!(mint_response.status().is_success());

    //dbg!(transaction);

    /*
    let db_locked = app.db.lock().await;
    let b = db_locked.get_spendable();
    dbg!(b);
    */
}
