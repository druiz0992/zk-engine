use curves::pallas::Fq;
use integration_tests::client::test_app::spawn_app;
use plonk_prover::client::circuits::{mint::MintCircuit, transfer::TransferCircuit};
use std::str::FromStr;

#[tokio::test]
async fn transfer_endpoint_returns_200_with_correct_input() {
    let transfer_amount = "10";
    let mut app = spawn_app().await;
    app.add_client_circuits(&[
        Box::new(MintCircuit::<1>::new()),
        Box::new(TransferCircuit::<1, 1, 8>::new()),
    ])
    .await
    .expect("Error adding new circuit");

    let preimage_files = vec![
        "./tests/data/mint_preimage_c1_v10.dat",
        "./tests/data/mint_preimage_c1_v100.dat",
    ];
    let block_files = vec!["./tests/data/block0_2_mints_c1_v10_c1_v100.dat"];
    let preimage = app
        .set_initial_state(preimage_files, block_files)
        .await
        .unwrap()
        .into_iter()
        .find(|p| *p.preimage.get_value() == Fq::from_str(transfer_amount).unwrap())
        .unwrap();

    let transfer_params = app
        .prepare_transfer_input(transfer_amount, vec![preimage])
        .await
        .unwrap();
    let response = app.post_transfer_request(&transfer_params).await;
    assert!(response.status().is_success());

    let sequencer_requests = app.get_sequencer_requests().await;
    assert!(
        sequencer_requests.is_ok(),
        "Sequencer did not receive the transaction"
    );

    app.get_sequencer_requests()
        .await
        .expect("Error retrieving transfer from sequencer");

    let transaction = sequencer_requests.unwrap();
    let is_valid = app.verify_transfer(transaction, transfer_params).await;
    assert!(is_valid);
}

#[tokio::test]
async fn transfer_endpoint_returns_500_if_circuit_not_registered() {
    let transfer_amount = "10";
    let mut app = spawn_app().await;
    app.add_client_circuits(&[Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    let preimage_files = vec![
        "./tests/data/mint_preimage_c1_v10.dat",
        "./tests/data/mint_preimage_c1_v100.dat",
    ];
    let block_files = vec!["./tests/data/block0_2_mints_c1_v10_c1_v100.dat"];
    let preimage = app
        .set_initial_state(preimage_files, block_files)
        .await
        .unwrap()
        .into_iter()
        .find(|p| *p.preimage.get_value() == Fq::from_str(transfer_amount).unwrap())
        .unwrap();

    let transfer_params = app
        .prepare_transfer_input(transfer_amount, vec![preimage])
        .await
        .unwrap();
    let response = app.post_transfer_request(&transfer_params).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        response.status()
    );
}

#[tokio::test]
async fn transfer_endpoint_returns_500_with_incorrect_input() {
    let transfer_amount = "10";
    let mut app = spawn_app().await;
    app.add_client_circuits(&[
        Box::new(MintCircuit::<1>::new()),
        Box::new(TransferCircuit::<1, 1, 8>::new()),
    ])
    .await
    .expect("Error adding new circuit");

    let preimage_files = vec!["./tests/data/mint_preimage_c1_v100.dat"];
    let block_files = vec!["./tests/data/block0_2_mints_c1_v10_c1_v100.dat"];
    let preimage = app
        .set_initial_state(preimage_files, block_files)
        .await
        .unwrap();

    let transfer_params = app
        .prepare_transfer_input(transfer_amount, vec![preimage[0]])
        .await
        .unwrap();
    let response = app.post_transfer_request(&transfer_params).await;
    assert_eq!(
        response.status(),
        reqwest::StatusCode::INTERNAL_SERVER_ERROR,
        "Expected a 500  Internal Server Error, but got {}",
        response.status()
    );
}
