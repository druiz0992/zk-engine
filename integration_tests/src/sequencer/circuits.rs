use super::test_app::SequencerTestApp;
use curves::{pallas::PallasConfig, vesta::VestaConfig};
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::utils::vk_tree::build_vk_tree;
use sequencer::ports::storage::GlobalStateStorage;
use sequencer::services::prover::in_mem_sequencer_prover::InMemProver;
use sequencer::services::prover::{generate_and_store_cks, generate_and_store_client_circuit_vks};

impl SequencerTestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>>,
    ) -> anyhow::Result<()> {
        let mut prover = self.prover.lock().await;
        let mut db = self.db.lock().await;

        let vks = generate_and_store_client_circuit_vks::<
            PallasConfig,
            VestaConfig,
            _,
            _,
            InMemProver<VestaConfig, _, PallasConfig, _>,
        >(&mut prover, &circuits);

        let vk_tree = build_vk_tree(&vks);
        db.store_vk_tree(vk_tree);

        generate_and_store_cks::<
            VestaConfig,
            _,
            PallasConfig,
            _,
            InMemProver<VestaConfig, _, PallasConfig, _>,
        >(&mut prover);

        Ok(())
    }
}
