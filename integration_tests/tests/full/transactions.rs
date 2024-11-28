use integration_tests::client::mint::MintParams;
use integration_tests::test_app::spawn_app;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn send_2_mint_transactions() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_response = app.client.post_mint_request(mint_params).await;
    assert!(mint_response.status().is_success());

    let mint_response = app.client.post_mint_request(mint_params).await;
    assert!(mint_response.status().is_success());

    let transactions = app
        .sequencer
        .get_transactions()
        .await
        .expect("Error decoding transactions from sequencer");
    assert_eq!(
        transactions.len(),
        2,
        "Sequencer should have 2 transactions stored in memory and only has {}",
        transactions.len()
    );

    let block = app
        .sequencer
        .post_sequence()
        .await
        .expect("Error requesting a new Sequence");
    dbg!(block);
}
