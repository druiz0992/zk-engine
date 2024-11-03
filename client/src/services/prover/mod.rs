pub mod in_memory_prover {
    use ark_ec::{
        pairing::Pairing,
        short_weierstrass::{Affine, Projective, SWCurveConfig},
        CurveConfig, CurveGroup,
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

    use crate::{domain::CircuitType, ports::prover::Prover};
    use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;
    use plonk_prover::{
        client::{self, ClientPlonkCircuit},
        primitives::circuits::kem_dem::KemDemParams,
    };

    pub struct InMemProver<V: Pairing>
    where
        V: Pairing,
        <V::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    {
        pub key_storage: HashMap<String, ProvingKey<V>>,
    }

    impl<V> InMemProver<V>
    where
        V: Pairing,
        <V::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    {
        pub fn new() -> Self {
            Self {
                key_storage: HashMap::new(),
            }
        }
    }

    impl<V> Default for InMemProver<V>
    where
        V: Pairing,
        <V::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = V::BaseField>,
    {
        fn default() -> Self {
            InMemProver::new()
        }
    }

    impl<V, VSW> Prover<V, VSW> for InMemProver<V>
    where
        V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>>,
        <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,

        <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,
        VSW: SWCurveConfig<
            BaseField = <V as Pairing>::BaseField,
            ScalarField = <V as Pairing>::ScalarField,
        >,
    {
        fn prove<P, const C: usize, const N: usize, const D: usize>(
            circuit: &dyn ClientPlonkCircuit<P, V, VSW, C, N, D>,
            circuit_inputs: CircuitInputs<P, C, N, D>,
            proving_key: Option<&ProvingKey<V>>,
        ) -> Result<
            (
                Proof<V>,
                Vec<V::ScalarField>,
                DensePolynomial<V::ScalarField>,
                ProvingKey<V>,
            ),
            CircuitError,
        >
        where
            P: SWCurveConfig<BaseField = V::ScalarField>,
            <P as CurveConfig>::BaseField: KemDemParams<Field = V::ScalarField>,
        {
            // Convert the Vec to an array, checking for exactly 8 elements
            let mut circuit = client::build_plonk_circuit_from_inputs(circuit, circuit_inputs)?;
            ark_std::println!("Constraint count: {}", circuit.num_gates());
            let now = Instant::now();

            circuit.finalize_for_arithmetization()?;
            let mut rng = ChaChaRng::from_entropy();
            let pk = proving_key.map_or_else(
                || {
                    let (pk, _) = client::generate_keys_from_plonk::<P, V, VSW>(&mut circuit)?;
                    Ok::<ProvingKey<V>, CircuitError>(pk)
                },
                |pkey| Ok(pkey.clone()),
            )?;

            ark_std::println!("Preprocess done: {:?}", now.elapsed());

            let _public_inputs = circuit.public_input()?;
            let now = Instant::now();

            let (proof, g_poly, _) = PlonkIpaSnark::<V>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<V as Pairing>::BaseField>,
            >(&mut rng, &circuit, &pk, None)?;
            ark_std::println!("Proof done: {:?}", now.elapsed());

            Ok((proof, circuit.public_input()?, g_poly, pk.clone()))
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

        fn store_pk(&mut self, circuit_type: CircuitType, pk: ProvingKey<V>) {
            self.key_storage
                .entry(circuit_type.to_string())
                .or_insert(pk);
        }

        fn get_pk(&self, circuit_type: CircuitType) -> Option<&ProvingKey<V>> {
            self.key_storage.get(&circuit_type.to_string())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{InMemProver, Prover};
    use plonk_prover::client::circuits::transfer;

    use crate::domain::CircuitType;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use plonk_prover::client::{
        self,
        circuits::mint::{self, MintCircuit},
        circuits::transfer::TransferCircuit,
    };

    #[test]
    fn test_new_initialization() {
        let prover: InMemProver<VestaConfig> = InMemProver::new();
        assert!(
            prover.key_storage.is_empty(),
            "Key storage should be empty on initialization"
        );
    }

    #[test]
    fn test_default_initialization() {
        let prover: InMemProver<VestaConfig> = InMemProver::default();
        assert!(
            prover.key_storage.is_empty(),
            "Key storage should be empty on initialization"
        );
    }

    #[test]
    fn test_store_pk() {
        const C: usize = 1;
        const N: usize = 1;
        const D: usize = 8;
        let mut prover: InMemProver<VestaConfig> = InMemProver::default();

        let mint_circuit = mint::MintCircuit::new();
        let mint_inputs =
            mint::utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(
                &format!(
                    "Error generating random inputs for mint circuit with C:{C}, N:{N}, D:{D}"
                ),
            );
        let (mint_pk, _) =
            client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
                &mint_circuit,
                mint_inputs.clone(),
            )
            .expect(&format!(
                "Error generating key for mint circuit from random inputs with C:{C}, N:{N}, D:{D}"
            ));

        let transfer_circuit = TransferCircuit::new();
        let transfer_inputs =
            transfer::utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(
                &format!(
                    "Error generating random inputs for transfer circuit with C:{C}, N:{N}, D:{D}"
                ),
            );
        let (transfer_pk, _) =
            client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
                &transfer_circuit,
                transfer_inputs.clone(),
            )
            .expect(&format!(
            "Error generating key for transfer circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        prover.store_pk(CircuitType::Mint, mint_pk.clone());
        prover.store_pk(CircuitType::Transfer, transfer_pk.clone());

        let stored_mint_pk = prover.get_pk(CircuitType::Mint).unwrap();
        assert_eq!(stored_mint_pk, &mint_pk);

        let stored_transfer_pk = prover.get_pk(CircuitType::Transfer).unwrap();
        assert_eq!(stored_transfer_pk, &transfer_pk);
    }

    #[test]
    fn test_prove_and_verify_mint() {
        const C: usize = 1;
        const N: usize = 1;
        const D: usize = 8;

        let mint_circuit = MintCircuit::new();
        let inputs = mint::utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>()
            .expect(&format!(
                "Error generating random inputs for mint circuit with C:{C}, N:{N}, D:{D}"
            ));
        let (pk, vk) = client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            &mint_circuit,
            inputs.clone(),
        )
        .expect(&format!(
            "Error generating key for mint circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        let result =
            <InMemProver<VestaConfig> as Prover<_, _>>::prove(&mint_circuit, inputs, Some(&pk));
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );

        let (proof, public_inputs, _, _) = result.unwrap();
        let is_valid = <InMemProver<VestaConfig> as Prover<_, _>>::verify(vk, public_inputs, proof);

        assert!(is_valid, "Verification should succeed for a valid proof");
    }

    #[test]
    fn test_prove_and_verify_transfer() {
        const C: usize = 2;
        const N: usize = 2;
        const D: usize = 8;

        let transfer_circuit = TransferCircuit::new();
        let inputs = transfer::utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
        )
        .expect(&format!(
            "Error generating random inputs for transfer circuit with C:{C}, N:{N}, D:{D}"
        ));
        let (pk, vk) = client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            &transfer_circuit,
            inputs.clone(),
        )
        .expect(&format!(
            "Error generating key for transfer circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));

        let result =
            <InMemProver<VestaConfig> as Prover<_, _>>::prove(&transfer_circuit, inputs, Some(&pk));
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );
        let (proof, public_inputs, _, _) = result.unwrap();
        let is_valid = <InMemProver<VestaConfig> as Prover<_, _>>::verify(vk, public_inputs, proof);

        assert!(is_valid, "Verification should succeed for a valid proof");
    }
}
