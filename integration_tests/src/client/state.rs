use super::test_app::ClientTestApp;
use crate::common::utils::{read_block_from_file, read_preimage_from_file};
use anyhow::Result;
use client::domain::StoredPreimageInfo;
use curves::pallas::PallasConfig;
use serde_json::json;

impl ClientTestApp {
    pub async fn set_initial_state(
        &self,
        preimage_files: Vec<&str>,
        block_files: Vec<&str>,
    ) -> Result<Vec<StoredPreimageInfo<PallasConfig>>> {
        let mut preimages: Vec<StoredPreimageInfo<PallasConfig>> = Vec::new();
        for preimage_file in preimage_files {
            preimages.push(read_preimage_from_file(preimage_file)?);
        }
        self.insert_preimages(preimages)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        for block_file in block_files {
            let block = read_block_from_file(block_file)?;
            let body = json!(block);

            self.api_client
                .post(format!("{}/block", self.address))
                .json(&body)
                .send()
                .await
                .unwrap();
        }

        Ok(self.get_preimages().await)
    }
}
