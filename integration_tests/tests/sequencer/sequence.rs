use common::structs::Transaction;
use integration_tests::common::utils;
use integration_tests::sequencer::test_app::spawn_app;
use plonk_prover::client::circuits::mint::MintCircuit;
use plonk_prover::client::circuits::transfer::TransferCircuit;

#[tokio::test]
async fn post_sequence_after_posting_2_mint_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    // Add first transaction
    let mint_transaction =
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap();
    app.post_transaction(&mint_transaction).await.unwrap();

    // Add second transaction
    let mint_transaction =
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat")
            .unwrap();
    app.post_transaction(&mint_transaction).await.unwrap();

    let block = app.post_sequence().await.unwrap();
    assert_eq!(block.commitments.len(), 2);
    assert_eq!(block.nullifiers.len(), 0);
    assert_eq!(block.block_number, 0);

    let client_requests = app.get_client_requests().await;
    assert!(client_requests.is_ok());
}

#[tokio::test]
async fn post_sequence_after_posting_2_transfer_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(TransferCircuit::<1, 1, 8>::new()),
    ])
    .await
    .expect("Error adding new circuit");

    let mut transactions: Vec<Transaction<_>> = vec![];

    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap(),
    );
    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat")
            .unwrap(),
    );

    app.new_block(&transactions).await.unwrap();
    //app.post_transaction(&transactions[0]).await.unwrap();
    //app.post_transaction(&transactions[1]).await.unwrap();
    //let mut block = app.post_sequence().await.unwrap();

    transactions[0] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v10.dat")
            .unwrap();
    transactions[1] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v100.dat")
            .unwrap();

    app.post_transaction(&transactions[0]).await.unwrap();
    app.post_transaction(&transactions[1]).await.unwrap();

    app.post_sequence().await.unwrap();
}

#[tokio::test]
async fn post_sequence_after_posting_duplicated_transfer_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(TransferCircuit::<1, 1, 8>::new()),
    ])
    .await
    .expect("Error adding new circuit");

    let mut transactions: Vec<Transaction<_>> = vec![];

    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap(),
    );
    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat")
            .unwrap(),
    );

    app.new_block(&transactions).await.unwrap();
    //app.post_transaction(&transactions[0]).await.unwrap();
    //app.post_transaction(&transactions[1]).await.unwrap();
    //let mut block = app.post_sequence().await.unwrap();

    transactions[0] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v10.dat")
            .unwrap();
    transactions[1] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v10.dat")
            .unwrap();

    app.post_transaction(&transactions[0]).await.unwrap();
    app.post_transaction(&transactions[1]).await.unwrap();

    let response = app.post_sequence().await;
    assert!(response.is_err());
}

#[tokio::test]
async fn post_2_sequences_after_posting_4_transfer_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![
        Box::new(MintCircuit::<1>::new()),
        Box::new(TransferCircuit::<1, 1, 8>::new()),
    ])
    .await
    .expect("Error adding new circuit");

    let mut transactions: Vec<Transaction<_>> = vec![];

    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap(),
    );
    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat")
            .unwrap(),
    );

    app.new_block(&transactions).await.unwrap();
    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v1000.dat")
            .unwrap(),
    );
    transactions.push(
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v2000.dat")
            .unwrap(),
    );

    app.new_block(&transactions).await.unwrap();
    //app.post_transaction(&transactions[0]).await.unwrap();
    //app.post_transaction(&transactions[1]).await.unwrap();
    //let mut block = app.post_sequence().await.unwrap();

    transactions[0] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v10.dat")
            .unwrap();
    transactions[1] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v100.dat")
            .unwrap();

    app.post_transaction(&transactions[0]).await.unwrap();
    app.post_transaction(&transactions[1]).await.unwrap();

    app.post_sequence().await.unwrap();

    transactions[0] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v1000.dat")
            .unwrap();
    transactions[1] =
        utils::read_cbor_transaction_from_file("./tests/data/transfer_transaction_c1_v2000.dat")
            .unwrap();

    app.post_transaction(&transactions[0]).await.unwrap();
    app.post_transaction(&transactions[1]).await.unwrap();

    app.post_sequence().await.unwrap();
}
