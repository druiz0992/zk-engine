use super::TestApp;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

impl TestApp {
    pub async fn enable_client(&self) {
        Mock::given(path("/sequence"))
            .and(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.client_server)
            .await;
    }

    pub async fn get_client_requests(&self) -> usize {
        self.client_server.received_requests().await.unwrap().len()
    }
}
