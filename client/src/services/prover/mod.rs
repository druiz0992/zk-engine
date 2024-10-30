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
    use jf_relation::{
        errors::CircuitError, gadgets::ecc::SWToTEConParam, Arithmetization, Circuit,
    };
    use plonk_prover::{
        client::circuits::{mint::mint_circuit, transfer::transfer_circuit},
        primitives::circuits::kem_dem::KemDemParams,
    };
    use std::{collections::HashMap, time::Instant};

    use crate::{domain::CircuitType, ports::prover::Prover};
    use plonk_prover::client::circuits::circuit_inputs::CircuitInputs;

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
        fn prove<P>(
            circuit_type: CircuitType,
            circuit_inputs: CircuitInputs<P>,
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
            let mut circuit = match circuit_type {
                CircuitType::Mint => mint_circuit::<P, V, 1>(circuit_inputs)?,
                CircuitType::Transfer => transfer_circuit::<P, V, 1, 1, 8>(circuit_inputs)?,
                _ => panic!("Wrong circuit type"),
            };
            circuit.finalize_for_arithmetization()?;
            let mut rng = &mut jf_utils::test_rng();
            ark_std::println!("Constraint count: {}", circuit.num_gates());
            let now = Instant::now();
            let pk = if proving_key.is_none() {
                let srs = <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(
                    circuit.srs_size()?,
                    &mut rng,
                )?;
                let (pk, _) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit)?;
                pk
            } else {
                proving_key.unwrap().clone()
            };
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
            if self.key_storage.get(&circuit_type.to_string()).is_none() {
                self.key_storage.insert(circuit_type.to_string(), pk);
            }
        }

        fn get_pk(&self, circuit_type: CircuitType) -> Option<&ProvingKey<V>> {
            self.key_storage.get(&circuit_type.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{InMemProver, Prover};
    use plonk_prover::client::circuits::transfer::TransferCircuit;

    use crate::domain::CircuitType;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use plonk_prover::utils::key_gen::{generate_client_pks_and_vks, generate_dummy_mint_inputs};

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
        let mut prover: InMemProver<VestaConfig> = InMemProver::default();
        let pks = generate_client_pks_and_vks::<PallasConfig, VestaConfig, VestaConfig>().unwrap();
        prover.store_pk(CircuitType::Mint, pks[0].0.clone());
        prover.store_pk(CircuitType::Transfer, pks[1].0.clone());

        let mint_pk = prover.get_pk(CircuitType::Mint).unwrap();
        assert_eq!(mint_pk, &pks[0].0.clone());

        let transfer_pk = prover.get_pk(CircuitType::Transfer).unwrap();
        assert_eq!(transfer_pk, &pks[1].0.clone());
    }

    #[test]
    fn test_prove_and_verify_mint() {
        let pks = generate_client_pks_and_vks::<PallasConfig, VestaConfig, VestaConfig>().unwrap();
        let dummy_inputs = generate_dummy_mint_inputs::<PallasConfig, VestaConfig, VestaConfig>();

        let result = <InMemProver<VestaConfig> as Prover<_, _>>::prove(
            CircuitType::Mint,
            dummy_inputs,
            None,
        );
        assert!(
            result.is_ok(),
            "Proof generation should succeed for valid inputs"
        );

        let (proof, public_inputs, _, _) = result.unwrap();
        let vk = pks[0].1.clone();
        let is_valid = <InMemProver<VestaConfig> as Prover<_, _>>::verify(vk, public_inputs, proof);

        assert!(is_valid, "Verification should succeed for a valid proof");
    }

    #[test]
    fn test_prove_and_verify_transfer() {
        let transfer_circuit: TransferCircuit<PallasConfig, VestaConfig, VestaConfig> =
            TransferCircuit::new().unwrap();
        let result = <InMemProver<VestaConfig> as Prover<_, _>>::prove(
            CircuitType::Transfer,
            transfer_circuit.get_inputs(),
            Some(&transfer_circuit.get_proving_key()),
        );
        assert!(result.is_err(), "Proof generation should fail");
    }
}
