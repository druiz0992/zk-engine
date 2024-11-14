use std::{collections::HashMap, time::Instant};

use crate::{
    domain::{RollupCommitKeys, RollupProvingKeys},
    ports::prover::SequencerProver,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::errors::CircuitError;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::{Arithmetization, Circuit};
use plonk_prover::client::circuits::structs::CircuitId;
use plonk_prover::rollup::circuits::base::base_rollup_circuit;
use plonk_prover::rollup::circuits::client_input::ClientInput;
use zk_macros::sequencer_circuit;

#[sequencer_circuit]
pub struct InMemProver<V, VSW, P, SW> {
    pub proving_key_store: Option<RollupProvingKeys<V, VSW, P, SW>>,
    pub commit_key_store: Option<RollupCommitKeys<V, VSW, P, SW>>,
    pub verifying_key_store: HashMap<CircuitId, VerifyingKey<V>>,
}

#[sequencer_circuit]
impl<V, VSW, P, SW> InMemProver<V, VSW, P, SW> {
    pub fn new() -> Self {
        Self {
            proving_key_store: None,
            commit_key_store: None,
            verifying_key_store: HashMap::new(),
        }
    }
}

#[sequencer_circuit]
impl<V, VSW, P, SW> Default for InMemProver<V, VSW, P, SW> {
    fn default() -> Self {
        Self::new()
    }
}

#[sequencer_circuit]
impl<V, VSW, P, SW> SequencerProver<V, VSW, P, SW> for InMemProver<V, VSW, P, SW> {
    fn rollup_proof(
        client_inputs: [ClientInput<V, 1, 1, 8>; 2],
        global_vk_root: <V as Pairing>::BaseField,
        global_nullifier_root: <V as Pairing>::BaseField,
        global_nullifier_leaf_count: <V as Pairing>::BaseField,
        global_commitment_root: <V as Pairing>::BaseField,
        g_polys: [DensePolynomial<<V as Pairing>::ScalarField>; 2],
        commit_key: RollupCommitKeys<V, VSW, P, SW>,
        proving_keys: Option<RollupProvingKeys<V, VSW, P, SW>>,
    ) -> Result<Proof<P>, CircuitError> {
        let (mut circuit, _pi_star) = base_rollup_circuit::<V, P, 2, 1, 1, 8>(
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
            let srs = <PlonkIpaSnark<P> as UniversalSNARK<P>>::universal_setup_for_testing(
                circuit.srs_size()?,
                &mut rng,
            )?;
            ark_std::println!("SRS size {} done: {:?}", circuit.srs_size()?, now.elapsed());
            let now = Instant::now();
            let (pk, _vk) = PlonkIpaSnark::<P>::preprocess(&srs, &circuit)?;
            ark_std::println!("Preprocess done: {:?}", now.elapsed());
            pk
        };

        let now = Instant::now();

        assert!(circuit
            .check_circuit_satisfiability(&circuit.public_input().unwrap())
            .is_ok());

        let (proof, _g_poly, _) = PlonkIpaSnark::<P>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<P as Pairing>::BaseField>,
        >(&mut rng, &circuit, &pk, None)?;
        ark_std::println!("Proof done: {:?}", now.elapsed());
        Ok(proof)
    }

    fn store_pks(&mut self, pks: RollupProvingKeys<V, VSW, P, SW>) {
        self.proving_key_store = Some(pks);
    }

    fn get_pks(&self) -> Option<RollupProvingKeys<V, VSW, P, SW>> {
        self.proving_key_store.clone()
    }

    fn store_vk(&mut self, circuit_id: CircuitId, vk: VerifyingKey<V>) {
        self.verifying_key_store.insert(circuit_id, vk);
    }

    fn get_vk(&self, circuit_id: CircuitId) -> Option<VerifyingKey<V>> {
        ark_std::println!("Getting vk for {:?}", circuit_id);
        ark_std::println!("Capacity: {}", self.verifying_key_store.capacity());
        self.verifying_key_store.get(&circuit_id).cloned()
    }

    fn store_cks(&mut self, cks: RollupCommitKeys<V, VSW, P, SW>) {
        self.commit_key_store = Some(cks);
    }

    fn get_cks(&self) -> Option<RollupCommitKeys<V, VSW, P, SW>> {
        self.commit_key_store.clone()
    }
}
