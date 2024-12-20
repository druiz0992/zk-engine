use crate::services::{
    prover::in_memory_prover::InMemProver, storage::in_mem_storage::InMemStorage,
};
use adapters::rest_api::rest_api_entry::Application;
use common::services::notifier::HttpNotifier;
use common::{configuration, telemetry};
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};
use std::sync::Arc;
use tracing_log::log;
pub mod adapters;
pub mod domain;
pub mod ports;
pub mod services;
pub mod usecase;
pub mod utils;

fn main() -> anyhow::Result<()> {
    let configuration = configuration::get_configuration().expect("Failed to read configuration");
    telemetry::init_logger(
        "zk-engine::client",
        &configuration.log_level(),
        std::io::stdout,
    );
    log::trace!("Initializing");
    let db: InMemStorage<PallasConfig, Fq> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let mut prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();
    let notifier = HttpNotifier::new(configuration.sequencer);

    utils::circuits::init_client_circuits::<PallasConfig, VestaConfig, VestaConfig, _>(
        &mut prover,
    )?;

    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";
    let thread_safe_notifier = Arc::new(tokio::sync::Mutex::new(notifier));
    let async_rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .enable_time()
        .build()
        .unwrap();
    async_rt.block_on(async {
        let application = Application::build(
            thread_safe_db,
            thread_safe_prover,
            thread_safe_notifier,
            configuration.client,
        )
        .await
        .unwrap();
        application.run_until_stopped().await.unwrap();
    });

    Ok(())
}
