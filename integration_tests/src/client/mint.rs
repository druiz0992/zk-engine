use crate::common::utils::decimal_to_hex;

use super::test_app::ClientTestApp;
use client::domain::Preimage;
use client::ports::prover::Prover;
use client::services::prover::in_memory_prover::InMemProver;
use client::usecase::mint::inputs::build_mint_inputs;
use client::utils;
use common::structs::Transaction;
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_relation::constraint_system::Circuit;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use reqwest::Response;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct MintParams {
    pub value: String,
    pub token_id: String,
}

impl<'a> MintParams {
    pub fn new(value: &'a str, token_id: &'a str) -> Self {
        Self {
            value: value.to_string(),
            token_id: token_id.to_string(),
        }
    }

    pub fn new_vector(len: usize) -> Vec<Self> {
        let mut mint_params_vector = Vec::with_capacity(len);
        for _ in 0..len {
            mint_params_vector.push(MintParams::new(&len.to_string(), &len.to_string()));
        }
        mint_params_vector
    }
}

impl Default for MintParams {
    fn default() -> Self {
        Self {
            value: "1".to_string(),
            token_id: "1".to_string(),
        }
    }
}

#[derive(Clone, Serialize, Debug, Deserialize)]
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
            value: decimal_to_hex(value).unwrap(),
            token_id: decimal_to_hex(token_id).unwrap(),
            public_key: public_key.to_string(),
            salt: decimal_to_hex(&salt.to_string()).unwrap(),
        }
    }
}

impl ClientTestApp {
    pub async fn build_mint_request(&mut self, mint_values: &[MintParams]) -> Vec<MintRequestBody> {
        let user_keys = if let Some(keys) = &self.user_keys {
            keys.clone()
        } else {
            let user_keys = self
                .default_user_keys()
                .await
                .expect("Error generating user keys");
            self.set_user_keys(user_keys);
            self.get_user_keys().unwrap()
        };

        mint_values
            .iter()
            .map(|m| MintRequestBody::new(&m.value, &m.token_id, user_keys.public_key.as_str()))
            .collect()
    }

    pub async fn post_mint_request(&mut self, mint_request: &[MintRequestBody]) -> Response {
        let body = json!(mint_request);

        self.api_client
            .post(format!("{}/mint", self.address))
            .json(&body)
            .send()
            .await
            .unwrap()
    }

    pub async fn check_mint_preimages(&self, mint_params: &[MintParams]) {
        let preimages = self.get_preimages().await;
        assert_eq!(
            preimages.len(),
            mint_params.len(),
            "Expected {} preimage",
            mint_params.len()
        );

        preimages.iter().enumerate().for_each(|(i, p)| {
            let preimage = p.preimage;
            assert_eq!(
                *preimage.get_value(),
                curves::pallas::Fq::from_str(mint_params[i].value.as_str()).unwrap(),
                "Stored preimage value {} doesnt match with expected value {}",
                p.preimage.get_value(),
                mint_params[i].value,
            );
            assert_eq!(
                *preimage.get_token_id(),
                curves::pallas::Fq::from_str(mint_params[i].token_id.as_str()).unwrap(),
                "Stored preimage id {} doesnt match with expected id {}",
                preimage.get_token_id(),
                mint_params[i].token_id,
            );
        });
    }

    pub async fn verify_mint(
        &self,
        transaction: Transaction<VestaConfig>,
        preimage: Vec<Preimage<PallasConfig>>,
    ) -> bool {
        let circuit =
            utils::circuits::get_mint_circuit_from_params::<PallasConfig, VestaConfig, _>(
                preimage.len(),
            )
            .unwrap();
        let (_, vk) = circuit.generate_keys().unwrap();
        let circuit_inputs = build_mint_inputs::<PallasConfig, VestaConfig, _>(preimage).unwrap();
        let mint_circuit = circuit.to_plonk_circuit(circuit_inputs).unwrap();
        let public_inputs = mint_circuit.public_input().unwrap();
        <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::verify(
            vk,
            public_inputs,
            transaction.proof,
        )
    }
}
