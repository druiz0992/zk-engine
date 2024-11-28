use super::test_app::ClientTestApp;
use client::adapters::rest_api::structs::TransferInput;
use client::domain::StoredPreimageInfo;
use client::ports::committable::Committable;
use curves::pallas::{Fq, PallasConfig};
use reqwest::Response;
use serde_json::json;
use std::str::FromStr;

impl ClientTestApp {
    pub async fn prepare_transfer_input(
        &mut self,
        transfer_amount: &str,
        preimages: Vec<StoredPreimageInfo<PallasConfig>>,
    ) -> Result<TransferInput<PallasConfig>, String> {
        let user_keys = if self.user_keys.is_some() {
            self.get_user_keys_as_user_keys().await?
        } else {
            self.set_default_user_keys()
                .await
                .map_err(|e| e.to_string())?;
            self.get_user_keys_as_user_keys().await?
        };
        let mut commitments_to_use: Vec<Fq> = Vec::new();
        for preimage in preimages {
            commitments_to_use.push(
                preimage
                    .preimage
                    .commitment_hash()
                    .map_err(|e| e.to_string())?
                    .0,
            );
        }
        let transfer_request = TransferInput {
            transfer_amount: Fq::from_str(transfer_amount).unwrap(),
            commitments_to_use,
            sender: user_keys.public_key,
            recipient: user_keys.public_key,
        };

        Ok(transfer_request)
    }

    pub async fn post_transfer_request(
        &self,
        transfer_request: &TransferInput<PallasConfig>,
    ) -> Response {
        let body = json!(transfer_request);

        self.api_client
            .post(format!("{}/transfer", self.address))
            .json(&body)
            .send()
            .await
            .unwrap()
    }
}
