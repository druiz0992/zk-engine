use crate::helpers::spawn_app;
use plonk_prover::client::circuits::mint::MintCircuit;

#[tokio::test]
async fn mint_endpoint_returns_200_with_correct_input() {
    let mut app = spawn_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let mint_response = app.post_mint_request(vec![["1", "1"]]).await;

    assert!(mint_response.status().is_success());
}

#[tokio::test]
async fn mint_endpoint_returns_500_if_circuit_not_registered() {
    let app = spawn_app().await;
    let mint_response = app.post_mint_request(vec![["1", "1"]]).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}

#[tokio::test]
async fn mint_endpoint_returns_422_with_incorrect_input() {
    let app = spawn_app().await;
    let mint_response = app.post_mint_request(vec![["-1", "1"]]).await;

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

    app.add_client_circuits(vec![Box::new(MintCircuit::<4>::new())])
        .await
        .expect("Error adding new circuit");
    let mint_requests = vec![["1", "1"], ["2", "2"], ["3", "3"], ["4", "4"]];

    let mint_response = app.post_mint_request(mint_requests).await;

    assert!(mint_response.status().is_success());
}

#[tokio::test]
async fn mint_endpoint_returns_500_with_4_transactions_if_circuit_unregistered() {
    let app = spawn_app().await;
    let mint_requests = vec![["1", "1"], ["2", "2"], ["3", "3"], ["4", "4"]];

    let mint_response = app.post_mint_request(mint_requests).await;

    assert_eq!(
        mint_response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        mint_response.status()
    );
}
