use common::configuration;
use common::services::notifier::HttpNotifier;
use common::structs::Block;
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

pub struct SequencerTestApp {
    pub address: String,
    pub port: u16,
    pub prover: Arc<Mutex<InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig>>>,
    pub db: Arc<Mutex<InMemStorage>>,
    pub notifier: Arc<Mutex<HttpNotifier<Block<curves::vesta::Fr>>>>,
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

pub async fn spawn_app() -> SequencerTestApp {
    Lazy::force(&TRACING);
    let test_app = spawn_sequencer_app().await;
    test_app.enable_client().await;

    test_app
}

pub async fn spawn_sequencer_app() -> SequencerTestApp {
    let client_server = MockServer::start().await;
    let configuration = {
        let mut c = configuration::get_configuration().expect("Failed to read configuration");
        c.sequencer.port = 0;
        c.client.base_url = client_server.uri();
        c
    };

    let db: InMemStorage = InMemStorage::new();
    let thread_safe_db = std::sync::Arc::new(tokio::sync::Mutex::new(db));
    let prover: InMemProver<VestaConfig, VestaConfig, PallasConfig, PallasConfig> =
        InMemProver::new();
    let thread_safe_prover = Arc::new(tokio::sync::Mutex::new(prover));
    let notifier = HttpNotifier::new(configuration.client);
    let thread_safe_notifier = Arc::new(tokio::sync::Mutex::new(notifier));

    let application = Application::build(
        thread_safe_db.clone(),
        thread_safe_prover.clone(),
        thread_safe_notifier.clone(),
        configuration.sequencer.clone(),
    )
    .await
    .expect("Couldnt launch application");

    let application_port = application.port();

    tokio::spawn(application.run_until_stopped());

    let test_app = SequencerTestApp {
        address: format!("http://localhost:{}", application_port),
        port: application_port,
        prover: thread_safe_prover.clone(),
        db: thread_safe_db.clone(),
        notifier: thread_safe_notifier.clone(),
        api_client: reqwest::Client::new(),
        client_server,
    };
    println!("Sequencer listening at {}", test_app.address);

    test_app
}
