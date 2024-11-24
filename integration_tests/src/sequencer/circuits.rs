use curves::{pallas::PallasConfig, vesta::VestaConfig};

use super::test_app::SequencerTestApp;
use common::crypto::poseidon::Poseidon;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::structs::VK;
use jf_plonk::proof_system::UniversalSNARK;
use jf_primitives::pcs::StructuredReferenceString;
use plonk_prover::client::ClientPlonkCircuit;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use sequencer::domain::RollupCommitKeys;
use sequencer::ports::prover::SequencerProver;
use sequencer::ports::storage::GlobalStateStorage;
use trees::{membership_tree::Tree, tree::AppendTree};

impl SequencerTestApp {
    pub async fn add_client_circuits(
        &mut self,
        circuits: Vec<Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>>,
    ) -> anyhow::Result<()> {
        let mut prover = self.prover.lock().await;
        let mut db = self.db.lock().await;

        let vks = circuits
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                let keys = c.generate_keys().unwrap();
                prover.store_vk(c.get_circuit_type(), (keys.1.clone(), idx));
                keys.1
            })
            .collect::<Vec<VerifyingKey<_>>>();

        let poseidon: Poseidon<curves::vesta::Fq> = Poseidon::new();
        let vk_hashes = vks
            .iter()
            .map(|vk| {
                let vk_sigmas = vk.sigma_comms();
                let vk_selectors = vk.selector_comms();
                let vk_sigma_hashes = vk_sigmas
                    .iter()
                    .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
                let vk_selector_hashes = vk_selectors
                    .iter()
                    .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
                let vk_hashes = vk_sigma_hashes
                    .chain(vk_selector_hashes)
                    .collect::<Vec<_>>();
                let outlier_pair = vk_hashes[0..2].to_vec();
                let mut total_leaves = vk_hashes[2..].to_vec();
                for _ in 0..4 {
                    let lefts = total_leaves.iter().step_by(2);
                    let rights = total_leaves.iter().skip(1).step_by(2);
                    let pairs = lefts.zip(rights);
                    total_leaves = pairs
                        .map(|(&x, &y)| poseidon.hash_unchecked(vec![x, y]))
                        .collect::<Vec<_>>();
                }
                poseidon.hash_unchecked(vec![outlier_pair[0], outlier_pair[1], total_leaves[0]])
            })
            .collect::<Vec<_>>();

        let vk_tree = Tree::<curves::vesta::Fq, 8>::from_leaves(vk_hashes);
        db.store_vk_tree(vk_tree);

        let mut rng = ChaChaRng::from_entropy();
        let vesta_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
        let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

        let pallas_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
        let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();
        let rollup_commit_keys = RollupCommitKeys {
            pallas_commit_key,
            vesta_commit_key,
        };
        prover.store_cks(rollup_commit_keys);

        ////
        let mut processor = self.processor.lock().await;
        circuits.into_iter().for_each(|c| {
            let circuit_type = c.get_circuit_type();
            processor.register(circuit_type, c);
        });

        Ok(())
    }
}
