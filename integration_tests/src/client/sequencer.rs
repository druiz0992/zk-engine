use super::test_app::ClientTestApp;
use anyhow::Result;
use common::structs::Transaction;
use curves::vesta::VestaConfig;
use std::fs::File;
use std::io::Read;
use wiremock::matchers::{method, path};
use wiremock::{Mock, ResponseTemplate};

impl ClientTestApp {
    pub async fn enable_sequencer(&self) {
        Mock::given(path("/transactions"))
            .and(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&self.sequencer_server)
            .await;
    }

    pub async fn get_sequencer_requests(&self) -> Result<Transaction<VestaConfig>> {
        let body = self.get_sequencer_requests_as_bytes().await?;

        let transaction =
            serde_cbor::from_slice::<Transaction<VestaConfig>>(&body).map_err(|_| {
                anyhow::anyhow!("Error deserializing Transaction received by sequencer")
            })?;

        Ok(transaction)
    }

    pub async fn get_sequencer_requests_as_bytes(&self) -> Result<Vec<u8>> {
        let requests = self
            .sequencer_server
            .received_requests()
            .await
            .ok_or(anyhow::anyhow!("Error retrieving sequencer requests"))?;

        Ok(requests
            .last()
            .ok_or(anyhow::anyhow!("Error. No sequencer requests received"))?
            .body
            .clone())
    }

    pub fn read_sequencer_request_from_file(&self, path: &str) -> Result<Transaction<VestaConfig>> {
        // Open the file
        let mut file =
            File::open(path).map_err(|e| anyhow::anyhow!("Error opening file: {}", e))?;

        // Read the file content into a vector of bytes
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| anyhow::anyhow!("Error reading file: {}", e))?;

        // Attempt to convert the bytes into a UTF-8 string
        let utf8_str = String::from_utf8(buffer)
            .map_err(|_| anyhow::anyhow!("Error converting binary to UTF-8"))?;

        let transaction =
            serde_json::from_str::<Transaction<VestaConfig>>(&utf8_str).map_err(|_| {
                anyhow::anyhow!("Error deserializing Transaction received by sequencer")
            })?;

        Ok(transaction)
    }
}
