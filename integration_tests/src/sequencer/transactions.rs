use crate::sequencer::test_app::SequencerTestApp;
use anyhow::Result;
use common::structs::Transaction;
use curves::vesta::VestaConfig;
use serde_json::json;

impl SequencerTestApp {
    pub async fn post_transaction(&self, transaction: &Transaction<VestaConfig>) {
        let body = json!(transaction);
        let response = self
            .api_client
            .post(format!("{}/transactions", self.address))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert!(
            response.status().is_success(),
            "Sequencer should return Success on POST transction. Instead, it returned {}",
            response.status()
        );
    }
    pub async fn get_transactions(&self) -> Result<Vec<Transaction<VestaConfig>>> {
        let response = self
            .api_client
            .get(format!("{}/transactions", self.address))
            .send()
            .await
            .unwrap();

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Sequencer returned {}", response.status()));
        }

        let transactions = response
            .json::<Vec<Transaction<VestaConfig>>>()
            .await
            .map_err(|_| anyhow::anyhow!("Error serializing transactions from sequencer"))?;

        Ok(transactions)
    }
}
