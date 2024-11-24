use crate::client::test_app::{spawn_client_app, ClientTestApp};
use crate::sequencer::test_app::{spawn_sequencer_app, SequencerTestApp};
use common::configuration;
use common::telemetry;
use once_cell::sync::Lazy;

pub struct TestApp {
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

    let configuration = {
        let mut c = configuration::get_configuration().expect("Failed to read configuration");
        c.client.base_url = client_app.address.to_string();
        c.sequencer.base_url = sequencer_app.address.to_string();
        c
    };

    let test_app = TestApp {
        client: client_app,
        sequencer: sequencer_app,
    };

    {
        let mut client_notifier = test_app.client.notifier.lock().await;
        client_notifier.base_url = configuration.sequencer.base_url;
        let mut sequencer_notifier = test_app.sequencer.notifier.lock().await;
        sequencer_notifier.base_url = configuration.client.base_url;
    }

    test_app
}
