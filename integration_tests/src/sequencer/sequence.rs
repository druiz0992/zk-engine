use crate::sequencer::test_app::SequencerTestApp;
use anyhow::Result;
use common::structs::Block;

impl SequencerTestApp {
    pub async fn post_sequence(&self) -> Result<Block<curves::vesta::Fr>> {
        //let body = json!(transaction);
        let response = self
            .api_client
            .post(format!("{}/sequence", self.address))
            .send()
            .await
            .unwrap();

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Sequencer returned {}", response.status()));
        }

        let block = response
            .json::<Block<curves::vesta::Fr>>()
            .await
            .map_err(|_| anyhow::anyhow!("Error serializing Block from sequencer"))?;

        Ok(block)
    }
}
