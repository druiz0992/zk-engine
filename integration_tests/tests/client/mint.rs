use integration_tests::client::mint::MintParams;
use integration_tests::client::test_app::spawn_app;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn mint_endpoint_returns_200_with_correct_input() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];

    app.add_client_circuits(&[Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_request = app.build_mint_request(mint_params).await;
    let mint_response = app.post_mint_request(&mint_request).await;
    assert!(mint_response.status().is_success());

    let sequencer_requests = app.get_sequencer_requests().await;

    assert!(
        sequencer_requests.is_ok(),
        "Sequencer did not receive the transaction"
    );

    app.check_mint_preimages(mint_params).await;
    let transaction = sequencer_requests.unwrap();
    let preimage_info = app.get_preimages().await[0];

    let is_valid = app
        .verify_mint(transaction, vec![preimage_info.preimage])
        .await;
    assert!(is_valid);
}

#[tokio::test]
async fn mint_endpoint_returns_500_if_circuit_not_registered() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];
    let mint_request = app.build_mint_request(mint_params).await;
    let mint_response = app.post_mint_request(&mint_request).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}

#[tokio::test]
async fn mint_endpoint_returns_415_with_empty_input() {
    let app = spawn_app().await;

    let response = app
        .api_client
        .post(&format!("{}/mint", app.address))
        .send()
        .await
        .unwrap();

    assert_eq!(
        response.status(),
        reqwest::StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "Expected a 415  Unsupported Media Type error, but got {}",
        response.status()
    );
}

#[tokio::test]
async fn mint_endpoint_returns_200_with_4_transactions() {
    let mut app = spawn_app().await;

    app.add_client_circuits(&[Box::new(MintCircuit::<4>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_params = &MintParams::new_vector(4);

    let mint_request = app.build_mint_request(mint_params).await;
    let mint_response = app.post_mint_request(&mint_request).await;
    let sequencer_requests = app.get_sequencer_requests().await;

    assert!(mint_response.status().is_success());
    assert!(
        sequencer_requests.is_ok(),
        "Sequencer did not receive the transaction"
    );

    app.check_mint_preimages(mint_params).await;
    let transaction = sequencer_requests.unwrap();
    let preimage: Vec<_> = app
        .get_preimages()
        .await
        .iter()
        .map(|p| p.preimage)
        .collect();

    let is_valid = app.verify_mint(transaction, preimage).await;
    assert!(is_valid);
}

#[tokio::test]
async fn mint_endpoint_returns_500_with_4_transactions_if_circuit_unregistered() {
    let mut app = spawn_app().await;
    let mint_params = &MintParams::new_vector(4);

    let mint_request = app.build_mint_request(mint_params).await;
    let mint_response = app.post_mint_request(&mint_request).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}
