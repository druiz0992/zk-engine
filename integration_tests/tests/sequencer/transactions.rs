use integration_tests::common::utils;
use integration_tests::sequencer::test_app::spawn_app;
use reqwest::StatusCode;

#[tokio::test]
async fn post_correct_mint_transactions_returns_200() {
    let app = spawn_app().await;

    // Add first transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    let transactions = app.get_transactions().await.unwrap();
    assert_eq!(
        transactions.len(),
        1,
        "Sequencer should have 1 transaction stored in memory and instead it has {}",
        transactions.len()
    );

    // Add second transaction
    let mint_transaction =
        utils::read_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat").unwrap();
    app.post_transaction(&mint_transaction).await;

    let transactions = app.get_transactions().await.unwrap();
    assert_eq!(
        transactions.len(),
        2,
        "Sequencer should have 2 transaction stored in memory and instead it has {}",
        transactions.len()
    );
}

#[tokio::test]
async fn post_correct_transfer_transactions_returns_200() {
    let app = spawn_app().await;

    let transfer_transaction =
        utils::read_transaction_from_file("./tests/data/transfer_transaction_c1_v10.dat").unwrap();
    app.post_transaction(&transfer_transaction).await;

    let transactions = app.get_transactions().await.unwrap();
    assert_eq!(
        transactions.len(),
        1,
        "Sequencer should have 1 transaction stored in memory and instead it has {}",
        transactions.len()
    );

    let transfer_transaction =
        utils::read_transaction_from_file("./tests/data/transfer_transaction_c1_v100.dat").unwrap();
    app.post_transaction(&transfer_transaction).await;

    let transactions = app.get_transactions().await.unwrap();
    assert_eq!(
        transactions.len(),
        2,
        "Sequencer should have 2 transaction stored in memory and instead it has {}",
        transactions.len()
    );
}

#[tokio::test]
async fn post_empty_transactions_returns_415() {
    let app = spawn_app().await;

    let response = app
        .api_client
        .post(&format!("{}/transactions", app.address))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Sequencer should return Unsupported Media Type error 415 on empty POST transction. Instead, it returned {}",
        response.status()
    );
}
