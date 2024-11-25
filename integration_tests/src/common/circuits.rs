use crate::test_app::TestApp;
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::ClientPlonkCircuit;

impl TestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>>,
    ) -> anyhow::Result<()> {
        self.client.add_client_circuits(&circuits).await?;
        self.sequencer.add_client_circuits(circuits).await
    }
}
