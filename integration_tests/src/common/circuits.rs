use crate::test_app::TestApp;
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::nightfall::ipa_structs::ProvingKey;

use anyhow::anyhow;
use client::ports::prover::Prover;
use plonk_prover::client::ClientPlonkCircuit;

impl TestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: &[Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>],
    ) -> anyhow::Result<()> {
        self.client.add_client_circuits(circuits).await?;
        self.sequencer.add_client_circuits(circuits).await
    }
}
