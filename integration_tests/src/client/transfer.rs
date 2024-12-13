use super::test_app::ClientTestApp;
use ark_ff::UniformRand;
use client::adapters::rest_api::structs::TransferInput;
use client::domain::StoredPreimageInfo;
use client::ports::committable::Committable;
use client::ports::prover::Prover;
use client::services::prover::in_memory_prover::InMemProver;
use client::usecase::transfer::inputs::build_transfer_inputs;
use client::utils;
use common::structs::Transaction;
use curves::{
    pallas::{Fq, PallasConfig},
    vesta::VestaConfig,
};
use jf_relation::Circuit;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use reqwest::Response;
use serde_json::json;
use std::str::FromStr;

impl ClientTestApp {
    pub async fn prepare_transfer_input(
        &mut self,
        transfer_amount: &str,
        preimages: Vec<StoredPreimageInfo<PallasConfig>>,
    ) -> Result<TransferInput<PallasConfig>, String> {
        let mut rng = ChaChaRng::from_entropy();
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
            eph_key: Some(Fq::rand(&mut rng)),
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

    pub async fn verify_transfer(
        &self,
        transaction: Transaction<VestaConfig>,
        transfer_params: TransferInput<PallasConfig>,
    ) -> bool {
        let circuit =
            utils::circuits::get_transfer_circuit_from_params::<PallasConfig, VestaConfig, _>(1, 1)
                .unwrap();
        let (_, vk) = circuit.generate_keys().unwrap();

        let circuit_inputs = build_transfer_inputs::<PallasConfig, VestaConfig, _, _>(
            self.db.clone(),
            transfer_params,
        )
        .await
        .unwrap();
        let transfer_circuit = circuit.to_plonk_circuit(circuit_inputs.clone()).unwrap();
        let public_inputs = transfer_circuit.public_input().unwrap();
        <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::verify(
            vk,
            public_inputs,
            transaction.proof,
        )
    }
}
