use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::nightfall::ipa_structs::ProvingKey;

use super::test_app::ClientTestApp;
use anyhow::anyhow;
use client::ports::prover::Prover;
use plonk_prover::client::{circuits::structs::CircuitId, ClientPlonkCircuit};

impl ClientTestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>>,
    ) -> anyhow::Result<()> {
        let mut prover = self.prover.lock().await;
        for c in circuits {
            let keys = c
                .generate_keys()
                .map_err(|e| anyhow!("Failed to generate keys: {:?}", e))?;
            prover.store_pk(c.get_circuit_id(), keys.0);
        }
        Ok(())
    }

    pub async fn get_client_circuit(
        &mut self,
        circuit_id: CircuitId,
    ) -> Option<ProvingKey<VestaConfig>> {
        let prover = self.prover.lock().await;
        prover.get_pk(circuit_id).cloned()
    }
}
