use client::domain::{PreimageStatus, StoredPreimageInfo};
use curves::pallas::PallasConfig;
use integration_tests::client::test_app::spawn_app;
use integration_tests::common::utils::read_block_from_file;
use integration_tests::common::utils::read_preimage_from_file;
use serde_json::json;

#[tokio::test]
async fn block_endpoint_returns_200_with_correct_input() {
    let app = spawn_app().await;
    let filename = "./tests/data/block_2_mints_c1_v10_c1_v100.dat";
    let block = read_block_from_file(filename).unwrap();
    let body = json!(block);

    let response = app
        .api_client
        .post(format!("{}/block", app.address))
        .json(&body)
        .send()
        .await
        .unwrap();

    assert!(response.status().is_success());
}

#[tokio::test]
async fn block_endpoint_returns_415_with_empty_input() {
    let app = spawn_app().await;

    let response = app
        .api_client
        .post(format!("{}/block", app.address))
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
async fn block_endpoint_updates_preimages_and_root() {
    let app = spawn_app().await;
    let mut preimages: Vec<StoredPreimageInfo<PallasConfig>> = Vec::new();

    let filename = "./tests/data/mint_preimage_c1_v10.dat";
    preimages.push(read_preimage_from_file(filename).unwrap());

    let filename = "./tests/data/mint_preimage_c1_v100.dat";
    preimages.push(read_preimage_from_file(filename).unwrap());

    app.insert_preimages(preimages).await.unwrap();

    let filename = "./tests/data/block_2_mints_c1_v10_c1_v100.dat";
    let block = read_block_from_file(filename).unwrap();
    let body = json!(block);

    let root = app.get_root(block.block_number).await;
    assert!(root.is_none());

    let response = app
        .api_client
        .post(format!("{}/block", app.address))
        .json(&body)
        .send()
        .await
        .unwrap();

    let preimages = app.get_preimages().await;
    let root = app.get_root(block.block_number).await;

    assert!(response.status().is_success());
    assert_eq!(preimages[0].block_number, Some(0));
    assert_eq!(preimages[0].leaf_index, Some(0));
    assert_eq!(preimages[0].status, PreimageStatus::Unspent);
    assert_eq!(preimages[1].block_number, Some(0));
    assert_eq!(preimages[1].leaf_index, Some(1));
    assert_eq!(preimages[1].status, PreimageStatus::Unspent);
    assert!(root.is_some());
}
