pub mod base;
pub mod bounce;
pub mod bounce_merge;
pub mod merge;
pub mod structs;

pub mod utils {
    use std::fs::File;

    use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};

    use ark_poly::univariate::DensePolynomial;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use jf_plonk::nightfall::ipa_structs::{CommitKey, Proof, VerifyingKey};
    use jf_relation::{
        errors::CircuitError,
        gadgets::{from_emulated_field, EmulationConfig},
        Circuit, PlonkCircuit, Variable,
    };
    use jf_utils::field_switching;
    use serde::{Deserialize, Serialize};

    use super::structs::{AccInstance, GlobalPublicInputs, SubTrees};

    // This is a helper to serialize
    pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut bytes = vec![];
        a.serialize_with_mode(&mut bytes, Compress::Yes)
            .map_err(serde::ser::Error::custom)?;
        s.serialize_bytes(&bytes)
    }

    // This is a helper to deserialize
    pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
        let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
        a.map_err(serde::de::Error::custom)
    }

    // This is a helper to enforce limb decomposition into Variables
    pub fn enforce_limb_decomposition<P: Pairing>(
        circuit: &mut PlonkCircuit<P::ScalarField>,
        a: &P::ScalarField,
    ) -> Result<(Vec<Variable>, Variable), CircuitError>
    where
        <P as Pairing>::ScalarField: EmulationConfig<<P as Pairing>::BaseField>,
    {
        // C2::scalar -> limbs of C2::base
        let limbed_val: Vec<P::BaseField> = from_emulated_field(*a);
        // limbs of C2::base -> values of C2::scalar -> variables
        let limb_vars: Vec<Variable> = limbed_val
            .into_iter()
            .map(|l_x| circuit.create_variable(field_switching(&l_x)))
            .collect::<Result<Vec<_>, _>>()?;
        let recombined_var: Variable =
            circuit.recombine_limbs(&limb_vars, <P as Pairing>::ScalarField::B)?;
        Ok((limb_vars, recombined_var))
    }

    #[derive(CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, Clone)]
    pub struct StoredProof<E, I>
    where
        E: Pairing,
        <E::G1 as CurveGroup>::Config: SWCurveConfig,
        I: Pairing<BaseField = E::ScalarField>,
    {
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub proof: Proof<E>,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub pub_inputs: (
            GlobalPublicInputs<curves::pallas::Fr>,
            SubTrees<curves::pallas::Fr>,
            AccInstance<I>,
            Vec<AccInstance<E>>,
        ),
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub vk: VerifyingKey<E>,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub commit_key: (CommitKey<PallasConfig>, CommitKey<VestaConfig>),
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub g_poly: DensePolynomial<E::ScalarField>,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
        pub pi_stars: (
            Vec<DensePolynomial<curves::pallas::Fr>>,
            DensePolynomial<curves::vesta::Fr>,
        ),
    }

    pub fn serial_to_file<E: Pairing, I: Pairing>(
        proof: Proof<E>,
        pub_inputs: (
            GlobalPublicInputs<curves::pallas::Fr>,
            SubTrees<curves::pallas::Fr>,
            AccInstance<I>,
            Vec<AccInstance<E>>,
        ),
        vk: VerifyingKey<E>,
        commit_key: (CommitKey<PallasConfig>, CommitKey<VestaConfig>),
        g_poly: DensePolynomial<E::ScalarField>,
        pi_stars: (
            Vec<DensePolynomial<curves::pallas::Fr>>,
            DensePolynomial<curves::vesta::Fr>,
        ),
        file_name: &str,
    ) where
        E: Pairing,
        <E::G1 as CurveGroup>::Config: SWCurveConfig,
        I: Pairing<BaseField = E::ScalarField>,
    {
        let file = File::create(file_name).unwrap();
        let stored_proof = StoredProof {
            proof,
            pub_inputs,
            vk,
            commit_key,
            g_poly,
            pi_stars,
        };
        serde_json::to_writer(file, &stored_proof).unwrap();
    }

    pub fn deserial_from_file<E, I>(file_name: &str) -> StoredProof<E, I>
    where
        E: Pairing,
        <E::G1 as CurveGroup>::Config: SWCurveConfig,
        I: Pairing<BaseField = E::ScalarField>,
    {
        let file = File::open(file_name).unwrap();
        serde_json::from_reader(file).unwrap()
    }
}
