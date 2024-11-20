use client::adapters::rest_api::rest_api_entry::Application;
use client::services::{
    prover::in_memory_prover::InMemProver, storage::in_mem_storage::InMemStorage,
};
use common::configuration;
use common::services::notifier::HttpNotifier;
use common::telemetry;
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};

use super::keys::UserKeysResponseBody;
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;
use wiremock::MockServer;

pub struct ClientTestApp {
    pub address: String,
    pub port: u16,
    pub prover: Arc<Mutex<InMemProver<PallasConfig, VestaConfig, VestaConfig>>>,
    pub db: Arc<Mutex<InMemStorage<PallasConfig, Fq>>>,
    pub api_client: reqwest::Client,
    pub user_keys: Option<UserKeysResponseBody>,
    pub sequencer_server: MockServer,
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

pub async fn spawn_app() -> ClientTestApp {
    Lazy::force(&TRACING);
    let test_app = spawn_client_app().await;
    test_app.enable_sequencer().await;

    test_app
}

pub async fn spawn_client_app() -> ClientTestApp {
    let sequencer_server = MockServer::start().await;
    let configuration = {
        let mut c = configuration::get_configuration().expect("Failed to read configuration");
        c.client.port = 0;
        c.sequencer.base_url = sequencer_server.uri();
        c
    };

    let db: InMemStorage<PallasConfig, Fq> = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();
    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let notifier = HttpNotifier::new(configuration.sequencer);
    let thread_safe_notifier = Arc::new(tokio::sync::Mutex::new(notifier));
    let _test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";

    let application = Application::build(
        thread_safe_db.clone(),
        thread_safe_prover.clone(),
        thread_safe_notifier.clone(),
        configuration.client.clone(),
    )
    .await
    .expect("Couldnt launch application");

    let application_port = application.port();

    let _ = tokio::spawn(application.run_until_stopped());

    let test_app = ClientTestApp {
        address: format!("http://localhost:{}", application_port),
        port: application_port,
        prover: thread_safe_prover.clone(),
        db: thread_safe_db.clone(),
        api_client: reqwest::Client::new(),
        user_keys: None,
        sequencer_server,
    };

    test_app
}
