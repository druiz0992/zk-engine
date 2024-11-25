use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::nightfall::ipa_structs::ProvingKey;

use super::test_app::ClientTestApp;
use anyhow::anyhow;
use client::ports::prover::Prover;
use common::structs::CircuitType;
use plonk_prover::client::ClientPlonkCircuit;

impl ClientTestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: &[Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>],
    ) -> anyhow::Result<()> {
        let mut prover = self.prover.lock().await;
        for c in circuits {
            let keys = c
                .generate_keys()
                .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;
            prover.store_pk(c.get_circuit_type(), keys.0);
        }
        Ok(())
    }

    pub async fn get_client_circuit(
        &mut self,
        circuit_type: CircuitType,
    ) -> Option<ProvingKey<VestaConfig>> {
        let prover = self.prover.lock().await;
        prover.get_pk(circuit_type).cloned()
    }
}
