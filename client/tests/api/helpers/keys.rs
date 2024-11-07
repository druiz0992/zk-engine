use super::TestApp;
use bip39::{Language, Mnemonic};
use itertools::Itertools;
use reqwest::Response;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct UserKeysRequestBody {
    pub mnemonic: String,
}

impl UserKeysRequestBody {
    pub fn new(mnemonic_count: usize, language: Language) -> Self {
        let mnemonic = Mnemonic::generate_in(language, mnemonic_count).unwrap();
        let mnemonic_str = mnemonic.words().join(" ");
        Self {
            mnemonic: mnemonic_str,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct UserKeysResponseBody {
    pub root_key: String,
    pub private_key: String,
    pub nullifier_key: String,
    pub public_key: String,
}

impl TestApp {
    pub async fn post_keys_request(&self, body: serde_json::Value) -> Response {
        self.api_client
            .post(&format!("{}/keys", self.address))
            .json(&body)
            .send()
            .await
            .expect("Failed execute POST /keys request")
    }
}
