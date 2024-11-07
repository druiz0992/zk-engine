use client::services::prover::in_memory_prover::InMemProver;
use client::utils;
use curves::{pallas::PallasConfig, vesta::VestaConfig};

use super::TestApp;
use plonk_prover::client::ClientPlonkCircuit;

impl TestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>>,
    ) -> anyhow::Result<()> {
        utils::circuits::add_client_circuits::<
            PallasConfig,
            VestaConfig,
            VestaConfig,
            InMemProver<PallasConfig, VestaConfig, VestaConfig>,
        >(&self.prover, circuits)
        .await
    }
}
