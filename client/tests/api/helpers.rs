use client::adapters::rest_api::rest_api_entry::Application;
use client::adapters::telemetry;
use client::configuration;
use client::services::{
    prover::in_memory_prover::InMemProver, storage::in_mem_storage::InMemStorage,
};
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};

use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod circuits;
pub mod keys;

pub struct TestApp {
    pub address: String,
    pub port: u16,
    pub prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
    pub db: Arc<Mutex<InMemStorage<PallasConfig, Fq>>>,
    pub api_client: reqwest::Client,
}

static TRACING: Lazy<()> = Lazy::new(|| {
    let c = configuration::get_configuration().expect("Failed to read configuration");
    let default_filter_level = c.general.log_level;
    let subscriber_name = "test".to_string();
    if std::env::var("TEST_LOG").is_ok() {
        telemetry::init_logger(&subscriber_name, &default_filter_level, std::io::stdout);
    } else {
        telemetry::init_logger(&subscriber_name, &default_filter_level, std::io::sink);
    }
});

pub async fn spawn_app() -> TestApp {
    Lazy::force(&TRACING);
    let configuration = {
        let mut c = configuration::get_configuration().expect("Failed to read configuration");
        c.application.port = 0;
        c
    };

    let db: InMemStorage<PallasConfig, Fq> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();

    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";

    let application = Application::build(
        thread_safe_db.clone(),
        thread_safe_prover.clone(),
        configuration.application.clone(),
    )
    .await
    .expect("Couldnt launch application");

    let application_port = application.port();

    let _ = tokio::spawn(application.run_until_stopped());

    let test_app = TestApp {
        address: format!("http://localhost:{}", application_port),
        port: application_port,
        prover: thread_safe_prover.clone(),
        db: thread_safe_db.clone(),
        api_client: reqwest::Client::new(),
    };

    test_app
}
