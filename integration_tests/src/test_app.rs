use crate::client::test_app::{spawn_client_app, ClientTestApp};
use crate::sequencer::test_app::{spawn_sequencer_app, SequencerTestApp};
use common::configuration;
use common::telemetry;
use once_cell::sync::Lazy;

pub struct TestApp {
    pub api_client: reqwest::Client,
    pub client: ClientTestApp,
    pub sequencer: SequencerTestApp,
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
    let client_app = spawn_client_app().await;
    let sequencer_app = spawn_sequencer_app().await;

    let test_app = TestApp {
        api_client: reqwest::Client::new(),
        client: client_app,
        sequencer: sequencer_app,
    };

    test_app
}
