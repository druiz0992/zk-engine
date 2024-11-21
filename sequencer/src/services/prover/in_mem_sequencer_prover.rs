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
use common::structs::CircuitType;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::errors::CircuitError;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::{Arithmetization, Circuit};
use plonk_prover::rollup::circuits::base::base_rollup_circuit;
use plonk_prover::rollup::circuits::client_input::ClientInput;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use tracing_log::log;
use zk_macros::sequencer_bounds;

#[sequencer_bounds]
pub struct InMemProver<V, VSW, P, SW> {
    pub proving_key_store: Option<RollupProvingKeys<V, VSW, P, SW>>,
    pub commit_key_store: Option<RollupCommitKeys<V, VSW, P, SW>>,
    pub verifying_key_store: HashMap<CircuitType, (VerifyingKey<V>, usize)>,
}

#[sequencer_bounds]
impl<V, VSW, P, SW> InMemProver<V, VSW, P, SW> {
    pub fn new() -> Self {
        Self {
            proving_key_store: None,
            commit_key_store: None,
            verifying_key_store: HashMap::new(),
        }
    }
}

#[sequencer_bounds]
impl<V, VSW, P, SW> Default for InMemProver<V, VSW, P, SW> {
    fn default() -> Self {
        Self::new()
    }
}

#[sequencer_bounds]
impl<V, VSW, P, SW> SequencerProver<V, VSW, P, SW> for InMemProver<V, VSW, P, SW> {
    fn rollup_proof(
        client_inputs: Vec<ClientInput<V>>,
        global_vk_root: <V as Pairing>::BaseField,
        global_nullifier_root: <V as Pairing>::BaseField,
        global_nullifier_leaf_count: <V as Pairing>::BaseField,
        global_commitment_root: <V as Pairing>::BaseField,
        g_polys: Vec<DensePolynomial<<V as Pairing>::ScalarField>>,
        commit_key: RollupCommitKeys<V, VSW, P, SW>,
        proving_keys: Option<RollupProvingKeys<V, VSW, P, SW>>,
    ) -> Result<Proof<P>, CircuitError> {
        let mut rng = ChaChaRng::from_entropy();
        log::debug!("Start rollup circuit");
        let (circuit, _pi_star) = base_rollup_circuit::<V, P, 8>(
            client_inputs,
            global_vk_root,
            global_nullifier_root,
            global_nullifier_leaf_count,
            global_commitment_root,
            g_polys,
            commit_key.vesta_commit_key,
        )?;

        log::debug!("Constraint count: {}", circuit.num_gates());

        let now = Instant::now();
        let pk = if let Some(pkey) = proving_keys {
            pkey.base_proving_key
        } else {
            let srs = <PlonkIpaSnark<P> as UniversalSNARK<P>>::universal_setup_for_testing(
                circuit.srs_size()?,
                &mut rng,
            )?;
            log::debug!("SRS size {} done: {:?}", circuit.srs_size()?, now.elapsed());
            let now = Instant::now();
            let (pk, _vk) = PlonkIpaSnark::<P>::preprocess(&srs, &circuit)?;
            log::debug!("Preprocess done: {:?}", now.elapsed());
            pk
        };

        let now = Instant::now();

        let (proof, _g_poly, _) = PlonkIpaSnark::<P>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<P as Pairing>::BaseField>,
        >(&mut rng, &circuit, &pk, None)?;
        log::debug!("Proof done: {:?}", now.elapsed());
        Ok(proof)
    }

    fn store_pks(&mut self, pks: RollupProvingKeys<V, VSW, P, SW>) {
        self.proving_key_store = Some(pks);
    }

    fn get_pks(&self) -> Option<RollupProvingKeys<V, VSW, P, SW>> {
        self.proving_key_store.clone()
    }

    fn store_vk(&mut self, circuit_type: CircuitType, vk_info: (VerifyingKey<V>, usize)) {
        self.verifying_key_store.insert(circuit_type, vk_info);
    }

    fn get_vk(&self, circuit_type: CircuitType) -> Option<(VerifyingKey<V>, usize)> {
        ark_std::println!("Getting vk info for {:?}", circuit_type);
        self.verifying_key_store.get(&circuit_type).cloned()
    }

    fn store_cks(&mut self, cks: RollupCommitKeys<V, VSW, P, SW>) {
        self.commit_key_store = Some(cks);
    }

    fn get_cks(&self) -> Option<RollupCommitKeys<V, VSW, P, SW>> {
        self.commit_key_store.clone()
    }
}
