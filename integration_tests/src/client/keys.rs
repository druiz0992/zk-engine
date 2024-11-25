use super::test_app::ClientTestApp;
use anyhow::anyhow;
use bip39::{Language, Mnemonic};
use itertools::Itertools;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;

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

impl Default for UserKeysRequestBody {
    fn default() -> Self {
        let test_mnemonic = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";
        Self {
            mnemonic: test_mnemonic.to_string(),
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

const MNEMONIC_COUNT: usize = 24;

impl ClientTestApp {
    pub async fn post_keys_request(&self, body: serde_json::Value) -> Response {
        self.api_client
            .post(format!("{}/keys", self.address))
            .json(&body)
            .send()
            .await
            .expect("Failed execute POST /keys request")
    }

    async fn build_user_keys(
        &self,
        mnemonic_request: UserKeysRequestBody,
    ) -> Result<UserKeysResponseBody, anyhow::Error> {
        let body = json!(mnemonic_request);
        let response = self.post_keys_request(body).await;

        if response.status().is_client_error() {
            return Err(anyhow!("Error requesting new user key"));
        }

        let user_keys: UserKeysResponseBody = response
            .json()
            .await
            .expect("Failed to deserialize response");

        if user_keys.root_key.is_empty()
            || user_keys.private_key.is_empty()
            || user_keys.nullifier_key.is_empty()
            || user_keys.public_key.is_empty()
        {
            return Err(anyhow!("Error deserializing key response"));
        }

        Ok(user_keys)
    }

    pub async fn default_user_keys(&self) -> Result<UserKeysResponseBody, anyhow::Error> {
        let mnemonic_request = UserKeysRequestBody::default();
        self.build_user_keys(mnemonic_request).await
    }

    pub async fn new_user_keys(&self) -> Result<UserKeysResponseBody, anyhow::Error> {
        let mnemonic_request = UserKeysRequestBody::new(MNEMONIC_COUNT, Language::English);
        self.build_user_keys(mnemonic_request).await
    }

    pub fn set_user_keys(&mut self, user_keys: UserKeysResponseBody) {
        self.user_keys = Some(user_keys);
    }
}
