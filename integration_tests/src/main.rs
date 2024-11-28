use clap::{Parser, Subcommand};
use curves::pallas::Fq;
use integration_tests::client::mint::MintParams;
use integration_tests::client::test_app::spawn_app as spawn_client_app;
use integration_tests::common::utils;
use integration_tests::sequencer::test_app::spawn_app as spawn_sequencer_app;
use plonk_prover::client::circuits::mint::MintCircuit;
use plonk_prover::client::circuits::transfer::TransferCircuit;
use std::str::FromStr;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Mint,
    Block,
    Transfer,
    All,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mint => build_mint_transactions().await,
        Commands::Block => build_block().await,
        Commands::Transfer => build_transfer_transactions().await,
        Commands::All => build_all().await,
    }
}

async fn build_mint_transactions() {
    let mut app = spawn_client_app().await;
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

    for mint_req in &mint_params {
        app.post_mint_request(&[mint_req.clone()]).await;
        let value = &mint_req.value;
        let filename = format!("./tests/data/mint_transaction_c1_v{}.dat", value);
        let body = app.get_sequencer_requests_as_bytes().await.unwrap();
        utils::save_to_file(&filename, &body).unwrap();
    }

    let preimages = app.get_preimages().await;

    let preimages_str = preimages
        .iter()
        .map(|p| serde_json::to_string(p).unwrap())
        .collect::<Vec<_>>();

    for i in 0..mint_params.len() {
        let value = preimages[i].preimage.get_value().to_string();
        let filename = format!("./tests/data/mint_preimage_c1_v{}.dat", value);
        utils::save_to_file(&filename, preimages_str[i].as_bytes()).unwrap();
    }
}
async fn build_block() {
    let mut app = spawn_sequencer_app().await;

    app.add_client_circuits(vec![Box::new(MintCircuit::<1>::new())])
        .await
        .expect("Error adding new circuit");

    // Add first transaction
    let mint_transaction =
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v10.dat")
            .expect("Error reading CBOR mint transaction");
    app.post_transaction(&mint_transaction)
        .await
        .expect("Error posting mint transaction to sequencer");

    // Add second transaction
    let mint_transaction =
        utils::read_cbor_transaction_from_file("./tests/data/mint_transaction_c1_v100.dat")
            .unwrap();
    app.post_transaction(&mint_transaction)
        .await
        .expect("Error posting mint transaction to sequencer");

    let block = app.post_sequence().await.unwrap();
    let json_block = serde_json::to_string(&block).unwrap();

    let filename = "./tests/data/block_2_mints_c1_v10_c1_v100.dat".to_string();
    integration_tests::common::utils::save_to_file(&filename, json_block.as_bytes()).unwrap();
}

async fn build_transfer_transactions() {
    let transfer_amount = ["10", "100"];
    let mut app = spawn_client_app().await;
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
    let block_files = vec!["./tests/data/block_2_mints_c1_v10_c1_v100.dat"];
    let preimages = app
        .set_initial_state(preimage_files, block_files)
        .await
        .unwrap();

    for amount in transfer_amount {
        let preimage = *preimages
            .iter()
            .find(|p| *p.preimage.get_value() == Fq::from_str(amount).unwrap())
            .unwrap();

        let transfer_params = app
            .prepare_transfer_input(amount, vec![preimage])
            .await
            .unwrap();
        app.post_transfer_request(&transfer_params).await;

        let filename = format!("./tests/data/transfer_transaction_c1_v{}.dat", amount);
        let body = app.get_sequencer_requests_as_bytes().await.unwrap();
        utils::save_to_file(&filename, &body).unwrap();
    }
}

async fn build_all() {
    build_mint_transactions().await;
    build_block().await;
    build_transfer_transactions().await;
}
