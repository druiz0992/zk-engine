use common::configuration;
use common::services::notifier::HttpNotifier;
use common::telemetry;
use curves::{pallas::PallasConfig, vesta::VestaConfig};

use once_cell::sync::Lazy;
use sequencer::adapters::rest_api::sequencer_api::Application;
use sequencer::services::{
    prover::in_mem_sequencer_prover::InMemProver, storage::in_mem_sequencer_storage::InMemStorage,
};
use std::sync::Arc;
use tokio::sync::Mutex;
use wiremock::MockServer;

pub mod circuits;
pub mod client;

pub struct TestApp {
    pub address: String,
    pub port: u16,
    pub prover: Arc<Mutex<InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig>>>,
    pub db: Arc<Mutex<InMemStorage>>,
    pub api_client: reqwest::Client,
    pub client_server: MockServer,
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
    let client_server = MockServer::start().await;
    let configuration = {
        let mut c = configuration::get_configuration().expect("Failed to read configuration");
        c.application.port = 0;
        c.sequencer.base_url = client_server.uri();
        c
    };

    let db: InMemStorage = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let prover: InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig> =
        InMemProver::new();
    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let notifier = HttpNotifier::new(configuration.sequencer);
    let thread_safe_notifier = Arc::new(tokio::sync::Mutex::new(notifier));

    let application = Application::build(
        thread_safe_db.clone(),
        thread_safe_prover.clone(),
        thread_safe_notifier.clone(),
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
        client_server,
    };

    test_app
}
