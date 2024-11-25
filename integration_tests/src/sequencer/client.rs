use super::test_app::SequencerTestApp;
use anyhow::Result;
use common::structs::Block;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

impl SequencerTestApp {
    pub async fn enable_client(&self) {
        Mock::given(path("/block"))
            .and(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&self.client_server)
            .await;
    }

    pub async fn get_client_requests(&self) -> Result<Block<curves::pallas::Fq>> {
        let body = self.get_client_requests_as_bytes().await?;

        let body = std::str::from_utf8(&body)
            .map_err(|_| anyhow::anyhow!("Error extracting sequencer response"))?;

        let block = serde_json::from_str::<Block<curves::pallas::Fq>>(body)
            .map_err(|_| anyhow::anyhow!("Error deserializing Block received by Client"))?;

        Ok(block)
    }

    pub async fn get_client_requests_as_bytes(&self) -> Result<Vec<u8>> {
        let requests = self
            .client_server
            .received_requests()
            .await
            .ok_or(anyhow::anyhow!("Error retrieving sequencer requests"))?;

        Ok(requests
            .last()
            .ok_or(anyhow::anyhow!("Error. No client requests received"))?
            .body
            .clone())
    }
}
