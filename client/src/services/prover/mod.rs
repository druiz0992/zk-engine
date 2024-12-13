pub mod in_memory_prover {
    use ark_ec::{
        pairing::Pairing,
        short_weierstrass::{Affine, Projective, SWCurveConfig},
        CurveConfig,
    };
    use ark_poly::univariate::DensePolynomial;
    use jf_plonk::{
        nightfall::{
            ipa_structs::{Proof, ProvingKey, VerifyingKey},
            PlonkIpaSnark,
        },
        proof_system::UniversalSNARK,
        transcript::RescueTranscript,
    };
    use jf_primitives::rescue::RescueParameter;
    use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam, Circuit};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::{collections::HashMap, time::Instant};

    use crate::ports::prover::Prover;
    use ark_ff::PrimeField;
    use common::crypto::poseidon::constants::PoseidonParams;
    use common::structs::CircuitType;
    use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
    use plonk_prover::client::ClientPlonkCircuit;
    use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
    use std::marker::PhantomData;
    use zk_macros::client_bounds;

    #[client_bounds]
    pub struct InMemProver<P, V, VSW> {
        pub key_storage: HashMap<CircuitType, ProvingKey<V>>,
        _marker: PhantomData<(P, VSW)>,
    }

    #[client_bounds]
    impl<P, V, VSW> InMemProver<P, V, VSW> {
        pub fn new() -> Self {
            Self {
                key_storage: HashMap::new(),
                _marker: PhantomData,
            }
        }
    }

    #[client_bounds]
    impl<P, V, VSW> Default for InMemProver<P, V, VSW> {
        fn default() -> Self {
            Self {
                key_storage: HashMap::new(),
                _marker: PhantomData,
            }
        }
    }

    #[client_bounds]
    impl<P, V, VSW> Prover<P, V, VSW> for InMemProver<P, V, VSW> {
        fn prove(
            circuit: &dyn ClientPlonkCircuit<P, V, VSW>,
            circuit_inputs: CircuitInputs<P>,
            proving_key: &ProvingKey<V>,
        ) -> Result<
            (
                Proof<V>,
                Vec<V::ScalarField>,
                DensePolynomial<V::ScalarField>,
            ),
            CircuitError,
        > {
            // Convert the Vec to an array, checking for exactly 8 elements
            let circuit = circuit.to_plonk_circuit(circuit_inputs)?;
            ark_std::println!("Constraint count: {}", circuit.num_gates());
            let now = Instant::now();

            let mut rng = ChaChaRng::from_entropy();

            ark_std::println!("Preprocess done: {:?}", now.elapsed());

            let _public_inputs = circuit.public_input()?;
            let now = Instant::now();

            let (proof, g_poly, _) = PlonkIpaSnark::<V>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<V as Pairing>::BaseField>,
            >(&mut rng, &circuit, proving_key, None)?;
            ark_std::println!("Proof done: {:?}", now.elapsed());

            Ok((proof, circuit.public_input()?, g_poly))
        }

        fn verify(
            vk: VerifyingKey<V>,
            public_inputs: Vec<<V as Pairing>::ScalarField>,
            proof: Proof<V>,
        ) -> bool {
            PlonkIpaSnark::<V>::verify::<RescueTranscript<<V as Pairing>::BaseField>>(
                &vk,
                &public_inputs,
                &proof,
                None,
            )
            .is_ok()
        }

        fn get_pk(&self, circuit_type: CircuitType) -> Option<&ProvingKey<V>> {
            self.key_storage.get(&circuit_type)
        }
        fn store_pk(&mut self, circuit_type: CircuitType, pk: ProvingKey<V>) {
            self.key_storage.entry(circuit_type).or_insert(pk);
        }
    }
}

#[cfg(test)]
mod tests {

    use super::in_memory_prover::InMemProver;
    use crate::ports::prover::Prover;
    use plonk_prover::client::circuits::transfer;

    use crate::utils::circuits;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use plonk_prover::client::{
        circuits::mint::{self, MintCircuit},
        circuits::transfer::TransferCircuit,
    };

    #[test]
    fn test_new_initialization() {
        let prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::new();
        assert!(
            prover.key_storage.is_empty(),
            "Pk storage should be empty on initialization"
        );
    }

    #[test]
    fn test_default_initialization() {
        let prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::default();
        assert!(
            prover.key_storage.is_empty(),
            "Pk storage should be empty on initialization"
        );
    }

    #[test]
    fn test_store_pk() {
        const C: usize = 1;
        const N: usize = 1;
        const D: usize = 8;

        let mut prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::default();
        let mint_circuit =
            mint::MintCircuit::<C>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        let (mint_pk, _mint_vk) = mint_circuit.generate_keys().expect(&format!(
            "Error generating key for mint circuit from random inputs with C:{C}"
        ));

        let transfer_circuit =
            TransferCircuit::<C, N, D>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        let (transfer_pk, _transfer_vk) = transfer_circuit.generate_keys().expect(&format!(
            "Error generating key for transfer circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        let mint_circuit = MintCircuit::<C>;
        prover.store_pk(mint_circuit.get_circuit_type(), mint_pk.clone());
        let transfer_circuit = TransferCircuit::<C, N, D>;
        prover.store_pk(transfer_circuit.get_circuit_type(), transfer_pk.clone());

        let mint_circuit = MintCircuit::<C>;
        let stored_mint_pk = prover.get_pk(mint_circuit.get_circuit_type()).unwrap();
        assert_eq!(stored_mint_pk, &mint_pk);

        let transfer_circuit = TransferCircuit::<C, N, D>;
        let stored_transfer_pk = prover.get_pk(transfer_circuit.get_circuit_type()).unwrap();
        assert_eq!(stored_transfer_pk, &transfer_pk);
    }

    #[test]
    fn test_prove_and_verify_mint() {
        const C: usize = 1;
        const N: usize = 1;
        const D: usize = 8;

        let mut prover: InMemProver<PallasConfig, VestaConfig, _> = InMemProver::default();
        let mint_circuit = MintCircuit::<C>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        let inputs = mint::utils::build_random_inputs::<PallasConfig, VestaConfig, _, C>(None)
            .expect(&format!(
                "Error generating random inputs for mint circuit with C:{C}, N:{N}, D:{D}"
            ));
        let (pk, vk) = mint_circuit.generate_keys().expect(&format!(
            "Error generating key for mint circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        let result = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::prove(
            &*mint_circuit,
            inputs.clone(),
            &pk,
        );
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );

        let (proof, public_inputs, _) = result.unwrap();
        let is_valid = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::verify(
            vk.clone(),
            public_inputs,
            proof,
        );

        assert!(is_valid, "Verification should succeed for a valid proof");

        circuits::init_client_circuits::<PallasConfig, VestaConfig, VestaConfig, _>(&mut prover)
            .expect("Error initializing client circuits");

        let stored_pk = prover
            .get_pk(
                MintCircuit::<C>::new()
                    .as_circuit::<PallasConfig, VestaConfig, VestaConfig>()
                    .get_circuit_type(),
            )
            .unwrap();
        let result = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::prove(
            &*mint_circuit,
            inputs,
            &stored_pk,
        );
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );

        let (proof, public_inputs, _) = result.unwrap();
        let is_valid = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::verify(
            vk.clone(),
            public_inputs,
            proof,
        );

        assert!(is_valid, "Verification should succeed for a valid proof");
    }

    #[test]
    fn test_prove_and_verify_transfer() {
        const C: usize = 2;
        const N: usize = 2;
        const D: usize = 8;

        let transfer_circuit =
            TransferCircuit::<C, N, D>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        let inputs = transfer::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>(None)
            .expect(&format!(
                "Error generating random inputs for transfer circuit with C:{C}, N:{N}, D:{D}"
            ));
        let (pk, vk) = transfer_circuit.generate_keys().expect(&format!(
            "Error generating key for transfer circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        let result = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::prove(
            &*transfer_circuit,
            inputs,
            &pk,
        );
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );
        let (proof, public_inputs, _) = result.unwrap();
        let is_valid = <InMemProver<PallasConfig, VestaConfig, _> as Prover<_, _, _>>::verify(
            vk,
            public_inputs,
            proof,
        );

        assert!(is_valid, "Verification should succeed for a valid proof");
    }
}
