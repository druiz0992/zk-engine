use super::TestApp;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use reqwest::Response;
use serde::Serialize;
use serde_json::json;

#[derive(Clone, Serialize, Debug)]
pub struct MintRequestBody {
    pub value: String,
    pub token_id: String,
    pub public_key: String,
    pub salt: String,
}

impl MintRequestBody {
    pub fn new(value: &str, token_id: &str, public_key: &str) -> Self {
        let mut rng = ChaChaRng::from_entropy();
        let salt: u128 = rng.gen();

        Self {
            value: value.to_string(),
            token_id: token_id.to_string(),
            public_key: public_key.to_string(),
            salt: salt.to_string(),
        }
    }
}

impl TestApp {
    pub async fn post_mint_request(&self, mint_values: Vec<[&str; 2]>) -> Response {
        let user_keys = if let Some(keys) = &self.user_keys {
            keys
        } else {
            &self
                .new_user_keys()
                .await
                .expect("Error generating user keys")
        };

        let mint_request: Vec<MintRequestBody> = mint_values
            .iter()
            .map(|m| MintRequestBody::new(m[0], m[1], &user_keys.public_key.as_str()))
            .collect();

        let body = json!(mint_request);

        let mint_response = self
            .api_client
            .post(&format!("{}/mint", self.address))
            .json(&body)
            .send()
            .await
            .unwrap();

        mint_response
    }
}
