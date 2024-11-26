use integration_tests::common::utils;
use integration_tests::sequencer::test_app::spawn_app;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn post_sequence_after_posting_2_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    // Add first transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    // Add second transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    let block = app.post_sequence().await.unwrap();
    assert_eq!(block.commitments.len(), 2);
    assert_eq!(block.nullifiers.len(), 0);
    assert_eq!(block.block_number, 0);

    let client_requests = app.get_client_requests().await;
    assert!(client_requests.is_ok());
}

#[tokio::test]
#[ignore]
async fn save_block_2_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    // Add first transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    // Add second transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    let block = app.post_sequence().await.unwrap();
    let json_block = serde_json::to_string(&block).unwrap();

    let filename = format!("./tests/data/block_2_mints_c1_v10_c1_v100.dat");
    integration_tests::common::utils::save_to_file(&filename, json_block.as_bytes()).unwrap();
}
