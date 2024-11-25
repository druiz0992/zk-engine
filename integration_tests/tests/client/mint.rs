use integration_tests::client::mint::MintParams;
use integration_tests::client::test_app::spawn_app;
use integration_tests::common;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn mint_endpoint_returns_200_with_correct_input() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];

    app.add_client_circuits(&[Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_response = app.post_mint_request(mint_params).await;
    let sequencer_requests = app.get_sequencer_requests().await;

    assert!(mint_response.status().is_success());
    assert!(
        sequencer_requests.is_ok(),
        "Sequencer did not receive the transaction"
    );

    app.check_mint_preimages(mint_params).await;
}

#[tokio::test]
async fn mint_endpoint_returns_500_if_circuit_not_registered() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::default()];
    let mint_response = app.post_mint_request(mint_params).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}

#[tokio::test]
async fn mint_endpoint_returns_422_with_incorrect_input() {
    let mut app = spawn_app().await;
    let mint_params = &[MintParams::new("-1", "1")];
    let mint_response = app.post_mint_request(mint_params).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::UNPROCESSABLE_ENTITY,
        "Expected a 422  Unprocessable Entity Error, but got {}",
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

    let mint_response = app.post_mint_request(mint_params).await;
    let sequencer_requests = app.get_sequencer_requests().await;

    assert!(mint_response.status().is_success());
    assert!(
        sequencer_requests.is_ok(),
        "Sequencer did not receive the transaction"
    );

    app.check_mint_preimages(mint_params).await;
}

#[tokio::test]
async fn mint_endpoint_returns_500_with_4_transactions_if_circuit_unregistered() {
    let mut app = spawn_app().await;
    let mint_params = &MintParams::new_vector(4);

    let mint_response = app.post_mint_request(mint_params).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}

#[tokio::test]
#[ignore]
async fn save_mints() {
    let mut app = spawn_app().await;
    let mint_params = vec![
        MintParams::new("100", "1"),
        MintParams::new("10", "1"),
        MintParams::new("1000", "1"),
        MintParams::new("2000", "1"),
        MintParams::new("10000", "1"),
    ];

    app.add_client_circuits(&[Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    for i in 0..mint_params.len() {
        app.post_mint_request(&[mint_params[i].clone()]).await;
        let value = &mint_params[i].value;
        let filename = format!("./tests/data/mint_transaction_c1_v{}.dat", value);
        let body = app.get_sequencer_requests_as_bytes().await.unwrap();
        common::utils::save_to_file(&filename, &body).unwrap();
    }

    let preimages = app.get_preimages().await;

    let preimages_str = preimages
        .iter()
        .map(|p| serde_json::to_string(p).unwrap())
        .collect::<Vec<_>>();

    for i in 0..mint_params.len() {
        let value = preimages[i].preimage.get_value().to_string();
        let filename = format!("./tests/data/mint_preimage_c1_v{}.dat", value);
        common::utils::save_to_file(&filename, preimages_str[i].as_bytes()).unwrap();
    }
}
