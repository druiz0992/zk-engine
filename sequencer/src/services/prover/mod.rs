pub mod in_mem_sequencer_prover {
    use std::{collections::HashMap, time::Instant};

    use crate::{
        domain::{RollupCommitKeys, RollupProvingKeys},
        ports::prover::SequencerProver,
    };
    use curves::pallas::{Fq, Fr};
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use jf_plonk::{
        nightfall::{ipa_structs::VerifyingKey, PlonkIpaSnark},
        proof_system::UniversalSNARK,
        transcript::RescueTranscript,
    };
    use jf_relation::{Arithmetization, Circuit};
    use plonk_prover::client::circuits::structs::CircuitId;
    use plonk_prover::rollup::circuits::base::base_rollup_circuit;

    pub struct InMemProver {
        pub proving_key_store: Option<RollupProvingKeys>,
        pub commit_key_store: Option<RollupCommitKeys>,
        pub verifying_key_store: HashMap<CircuitId, VerifyingKey<VestaConfig>>,
    }
    impl InMemProver {
        pub fn new() -> Self {
            Self {
                proving_key_store: None,
                commit_key_store: None,
                verifying_key_store: HashMap::new(),
            }
        }
    }

    impl Default for InMemProver {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SequencerProver<VestaConfig, PallasConfig, PallasConfig> for InMemProver {
        fn rollup_proof(
            client_inputs: [plonk_prover::rollup::circuits::base::ClientInput<VestaConfig, 1, 1>;
                2],
            global_vk_root: Fr,
            global_nullifier_root: Fr,
            global_nullifier_leaf_count: Fr,
            global_commitment_root: Fr,
            g_polys: [ark_poly::univariate::DensePolynomial<Fq>; 2],
            commit_key: RollupCommitKeys,
            proving_keys: Option<RollupProvingKeys>,
        ) -> Result<
            jf_plonk::nightfall::ipa_structs::Proof<PallasConfig>,
            jf_relation::errors::CircuitError,
        > {
            let (mut circuit, _pi_star) = base_rollup_circuit::<VestaConfig, PallasConfig, 2, 1, 1>(
                client_inputs,
                global_vk_root,
                global_nullifier_root,
                global_nullifier_leaf_count,
                global_commitment_root,
                g_polys,
                commit_key.vesta_commit_key,
            )?;

            circuit.finalize_for_arithmetization()?;
            let mut rng = &mut jf_utils::test_rng();
            ark_std::println!("Constraint count: {}", circuit.num_gates());
            let now = Instant::now();
            let pk = if let Some(pkey) = proving_keys {
                pkey.base_proving_key
            } else {
                let srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
                circuit.srs_size()?,
                &mut rng,
            )?;
                ark_std::println!("SRS size {} done: {:?}", circuit.srs_size()?, now.elapsed());
                let now = Instant::now();
                let (pk, _vk) = PlonkIpaSnark::<PallasConfig>::preprocess(&srs, &circuit)?;
                ark_std::println!("Preprocess done: {:?}", now.elapsed());
                pk
            };

            let now = Instant::now();

            assert!(circuit
                .check_circuit_satisfiability(&circuit.public_input().unwrap())
                .is_ok());

            let (proof, _g_poly, _) =
                PlonkIpaSnark::<PallasConfig>::prove_for_partial::<_, _, RescueTranscript<Fq>>(
                    &mut rng, &circuit, &pk, None,
                )?;
            ark_std::println!("Proof done: {:?}", now.elapsed());
            Ok(proof)
        }

        fn store_pks(&mut self, pks: RollupProvingKeys) {
            self.proving_key_store = Some(pks);
        }

        fn get_pks(&self) -> Option<RollupProvingKeys> {
            self.proving_key_store.clone()
        }

        fn store_vk(&mut self, circuit_id: CircuitId, vk: VerifyingKey<VestaConfig>) {
            self.verifying_key_store.insert(circuit_id, vk);
        }

        fn get_vk(&self, circuit_id: CircuitId) -> Option<VerifyingKey<VestaConfig>> {
            ark_std::println!("Getting vk for {:?}", circuit_id);
            ark_std::println!("Capacity: {}", self.verifying_key_store.capacity());
            self.verifying_key_store.get(&circuit_id).cloned()
        }

        fn store_cks(&mut self, cks: RollupCommitKeys) {
            self.commit_key_store = Some(cks);
        }

        fn get_cks(&self) -> Option<RollupCommitKeys> {
            self.commit_key_store.clone()
        }
    }
}
