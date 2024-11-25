use common::services::notifier::HttpNotifier;
use common::{configuration, telemetry};
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::ClientPlonkCircuit;
use sequencer::adapters::rest_api::sequencer_api::Application;
use sequencer::services::{
    prover::in_mem_sequencer_prover::InMemProver, storage::in_mem_sequencer_storage::InMemStorage,
};
use sequencer::services::{
    prover::{generate_and_store_cks, generate_and_store_client_circuit_vks},
    storage::generate_and_store_vk_tree,
};
use sequencer::usecase::block::TransactionProcessor;
use sequencer::utils::circuits::register_circuits;
use std::sync::Arc;
use tracing_log::log;

fn main() {
    let configuration = configuration::get_configuration().expect("Failed to read configuration");
    telemetry::init_logger(
        "zk-engine::client",
        &configuration.log_level(),
        std::io::stdout,
    );
    log::trace!("Initializing");
    let mut db: InMemStorage = InMemStorage::new();
    let mut prover = InMemProver::<VestaConfig, VestaConfig, PallasConfig, PallasConfig>::new();
    let notifier = HttpNotifier::new(configuration.client);
    let mut processor = TransactionProcessor::new();

    let client_circuit_info: Vec<
        Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>,
    > = sequencer::utils::circuits::select_client_circuits_sequencer();
    ark_std::println!("Generating Keys");
    let vks = generate_and_store_client_circuit_vks(&mut prover, &client_circuit_info);
    generate_and_store_vk_tree(&mut db, vks);
    ark_std::println!("Generating srs_1");
    generate_and_store_cks(&mut prover);
    ark_std::println!("Ck ready");
    register_circuits::<PallasConfig, VestaConfig, _>(&mut processor, client_circuit_info);

    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let thread_safe_prover = std::sync::Arc::new(tokio::sync::Mutex::new(prover));
    let thread_safe_notifier = Arc::new(tokio::sync::Mutex::new(notifier));
    let thread_safe_processor = Arc::new(tokio::sync::Mutex::new(processor));

    let async_rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let application = Application::build(
            thread_safe_db,
            thread_safe_prover,
            thread_safe_notifier,
            thread_safe_processor,
            configuration.sequencer,
        )
        .await
        .unwrap();
        application.run_until_stopped().await.unwrap();
    });
    ark_std::println!("Sequencer Ready");
}
