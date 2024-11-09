use super::TestApp;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

impl TestApp {
    pub async fn enable_sequencer(&self) {
        Mock::given(path("/transactions"))
            .and(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.sequencer_server)
            .await;
    }

    pub async fn get_sequencer_requests(&self) -> usize {
        self.sequencer_server
            .received_requests()
            .await
            .unwrap()
            .len()
    }
}
