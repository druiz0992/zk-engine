pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;

use sequencer::utils;
use services::{
    prover::{generate_and_store_cks, generate_and_store_vks},
    storage::generate_and_store_vk_tree,
};

use crate::{
    adapters::rest_api::sequencer_api::run_sequencer_api,
    services::{
        prover::in_mem_sequencer_prover::InMemProver,
        storage::in_mem_sequencer_storage::InMemStorage,
    },
};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::ClientPlonkCircuit;

fn main() {
    let mut db: InMemStorage = InMemStorage::new();
    let mut prover = InMemProver::<VestaConfig, VestaConfig, PallasConfig, PallasConfig>::new();

    let client_circuit_info: Vec<
        Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>,
    > = utils::circuits::select_client_circuits_sequencer();
    ark_std::println!("Generating Keys");
    let vks = generate_and_store_vks(&mut prover, client_circuit_info);
    generate_and_store_vk_tree(&mut db, vks);
    ark_std::println!("Generating srs_1");
    generate_and_store_cks(&mut prover);
    ark_std::println!("Ck ready");

    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let thread_safe_prover = std::sync::Arc::new(tokio::sync::Mutex::new(prover));

    let async_rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let _ = run_sequencer_api(thread_safe_db, thread_safe_prover).await;
    });
    ark_std::println!("Sequencer Ready");
}
