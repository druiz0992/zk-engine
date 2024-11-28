use crate::sequencer::test_app::SequencerTestApp;
use anyhow::Result;
use common::structs::Transaction;
use curves::vesta::VestaConfig;
use reqwest::header::CONTENT_TYPE;

impl SequencerTestApp {
    pub async fn post_transaction(&self, transaction: &Transaction<VestaConfig>) -> Result<()> {
        let cbor_data = serde_cbor::to_vec(&transaction)
            .map_err(|_| anyhow::anyhow!("Transaction couldnt be serialized"))?;
        let response = self
            .api_client
            .post(format!("{}/transactions", self.address))
            .header(CONTENT_TYPE, "application/cbor")
            .body(cbor_data)
            .send()
            .await
            .unwrap();

        assert!(
            response.status().is_success(),
            "Sequencer should return Success on POST transction. Instead, it returned {}",
            response.status()
        );
        Ok(())
    }
    pub async fn get_transactions(&self) -> Result<Vec<Transaction<VestaConfig>>> {
        let response = self
            .api_client
            .get(format!("{}/transactions", self.address))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("Error sending Get transaction request to sequencer"))?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Sequencer returned {}", response.status()));
        }

        let body = response
            .bytes()
            .await
            .map_err(|_| anyhow::anyhow!("Error retrieving transactions from sequencer"))?;

        let transactions: Vec<Transaction<VestaConfig>> = serde_cbor::from_slice(&body)
            .map_err(|_| anyhow::anyhow!("Error deserializing transactions from sequencer"))?;

        Ok(transactions)
    }
}
