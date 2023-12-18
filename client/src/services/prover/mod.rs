pub mod in_memory_prover {
    use ark_ec::{
        pairing::Pairing,
        short_weierstrass::{Affine, Projective, SWCurveConfig},
        CurveConfig, CurveGroup,
    };
    use ark_poly::univariate::DensePolynomial;
    use ark_std::str::FromStr;
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

    use crate::{
        domain::{CircuitInputs, CircuitType},
        ports::prover::Prover,
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
            Self {
                key_storage: HashMap::new(),
            }
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
            /// Prefix for hashes for zkp private ket and nullifier
            /// PRIVATE_KEY_PREFIX = keccak256('zkpPrivateKey'), need to update for Pasta
            const PRIVATE_KEY_PREFIX: &str =
                "2708019456231621178814538244712057499818649907582893776052749473028258908910";
            /// PRIVATE_KEY_PREFIX = keccak256('nullifierKey'), need to update for Pasta
            const NULLIFIER_PREFIX: &str =
                "7805187439118198468809896822299973897593108379494079213870562208229492109015";

            let pk_prefix = P::BaseField::from_str(PRIVATE_KEY_PREFIX)
                .map_err(|_| bip32::Error::Crypto)
                .unwrap();
            let nullifier_prefix = P::BaseField::from_str(NULLIFIER_PREFIX)
                .map_err(|_| bip32::Error::Crypto)
                .unwrap();

            let mut circuit = match circuit_type {
                CircuitType::Mint => mint_circuit::<P, V, 1>(
                    [circuit_inputs.token_values[0]],
                    [circuit_inputs.token_ids[0]],
                    [circuit_inputs.token_salts[0]],
                    [circuit_inputs.recipients[0].as_affine()],
                )?,
                CircuitType::Transfer => transfer_circuit::<P, V, 1, 1, 8>(
                    [circuit_inputs.old_token_values[0]],
                    [circuit_inputs.old_token_salts[0]],
                    [circuit_inputs.membership_path[0]
                        .clone()
                        .try_into()
                        .unwrap()],
                    [circuit_inputs.membership_path_index[0]],
                    [circuit_inputs.commitment_tree_root[0]],
                    [circuit_inputs.token_values[0]],
                    [circuit_inputs.token_salts[0]],
                    circuit_inputs.token_ids[0],
                    circuit_inputs.recipients[0].as_affine(),
                    circuit_inputs.root_key,
                    circuit_inputs.ephemeral_key,
                    pk_prefix,
                    nullifier_prefix,
                )?,
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

            let public_inputs = circuit.public_input()?;
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
