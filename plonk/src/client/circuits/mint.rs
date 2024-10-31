use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use jf_plonk::{
    nightfall::{
        ipa_structs::{ProvingKey, VerifyingKey},
        PlonkIpaSnark,
    },
    proof_system::UniversalSNARK,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    constraint_system::PlonkCircuit, errors::CircuitError, gadgets::ecc::SWToTEConParam,
    Arithmetization, Circuit,
};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use super::circuit_inputs::CircuitInputs;
use crate::{
    client::ClientPlonkCircuit,
    primitives::circuits::{
        kem_dem::KemDemParams,
        poseidon::{PoseidonGadget, PoseidonStateVar},
    },
};
use common::{
    crypto::poseidon::constants::PoseidonParams,
    keypair::{PrivateKey, PublicKey},
};
use macros::client_circuit;

// P: SWCurveConfig,
// <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,

// V: Pairing<ScalarField = P::BaseField>,
// V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
// <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
// <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,

// VSW: SWCurveConfig<
// BaseField = <V as Pairing>::BaseField,
// ScalarField = <V as Pairing>::ScalarField,
// >,

const N: usize = 0; // Number if nullifiers
const D: usize = 0; // Depth of Merkle Tree
const ZERO: u64 = 0;
const ONE: u64 = 1;
const POSEIDON_STATE_VAR_LEN: usize = 6;
const EPHEMERAL_KEY_LEN: usize = 2;
const CIPHERTEXT_LEN: usize = 3;

pub struct MintCircuit<V>
where
    V: Pairing,
    <V::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub proving_key: ProvingKey<V>,
    pub verifying_key: VerifyingKey<V>,
}

impl<V> MintCircuit<V>
where
    V: Pairing,
    <V::G1 as CurveGroup>::Config: SWCurveConfig,
{
    #[client_circuit]
    pub fn new<P, VSW, const C: usize>() -> Result<Self, CircuitError> {
        let circuit_inputs = build_default_inputs::<P, V, VSW, C, N, D>()?;
        let keys = generate_keys::<P, V, VSW, C, N, D>(circuit_inputs.clone())?;

        Ok(MintCircuit {
            proving_key: keys.0,
            verifying_key: keys.1,
        })
    }

    pub fn get_proving_key(&self) -> ProvingKey<V> {
        self.proving_key.clone()
    }

    pub fn get_verifying_key(&self) -> VerifyingKey<V> {
        self.verifying_key.clone()
    }
}

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize> ClientPlonkCircuit<P, V, C, N, D>
    for MintCircuit<V>
{
    fn generate_keys(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
        generate_keys::<P, V, VSW, C, N, D>(circuit_inputs)
    }

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
        mint_circuit::<P, V, C, N, D>(circuit_inputs)
    }
}

#[client_circuit]
fn build_default_inputs<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> Result<CircuitInputs<P, C, N, D>, CircuitError> {
    let one = P::ScalarField::from(ONE);
    let zero = V::ScalarField::from(ZERO);
    let pk = PrivateKey::from_scalar(one);

    let mut circuit_inputs_builder = CircuitInputs::<P, C, N, D>::new();
    circuit_inputs_builder
        .add_token_values(vec![zero; C])
        .add_token_ids(vec![zero; C])
        .add_token_salts(vec![zero; C])
        .add_recipients(vec![PublicKey::from_private_key(&pk); C])
        .build();
    check_params::<P, V, C, N, D>(&circuit_inputs_builder)?;
    Ok(circuit_inputs_builder)
}
/*
value: [V::ScalarField; C],
token_id: [V::ScalarField; C],
token_nonce: [V::ScalarField; C],
token_owner: [Affine<P>; C],
*/
// C is the number of output commitments
pub fn mint_circuit<P, V, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: CircuitInputs<P, C, N, D>,
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
where
    P: SWCurveConfig,
    V: Pairing<ScalarField = P::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
{
    check_params::<P, V, C, N, D>(&circuit_inputs)?;

    // Calculate output hash of the commitment
    let mut circuit = PlonkCircuit::new_turbo_plonk();
    // Swap_field = false
    circuit.create_public_boolean_variable(false)?;
    // We pretend N=1
    let commitment_root = V::ScalarField::from(0u64);
    circuit.create_public_variable(commitment_root)?;
    let nullifier = V::ScalarField::from(0u64);
    circuit.create_public_variable(nullifier)?;

    for i in 0..C {
        let commitment_preimage_var = [
            circuit_inputs.token_values[i],
            circuit_inputs.token_ids[i],
            circuit_inputs.token_salts[i],
            circuit_inputs.recipients[i].as_affine().x,
            circuit_inputs.recipients[i].as_affine().y,
        ]
        .iter()
        .map(|&v| circuit.create_variable(v))
        .collect::<Result<Vec<_>, _>>()?;
        let commitment_var = PoseidonGadget::<
            PoseidonStateVar<POSEIDON_STATE_VAR_LEN>,
            V::ScalarField,
        >::hash(&mut circuit, commitment_preimage_var.as_slice())?;
        circuit.set_variable_public(commitment_var)?;
    }

    let eph_pub_key = [V::ScalarField::from(0u64); EPHEMERAL_KEY_LEN];
    for e in eph_pub_key.iter() {
        circuit.create_public_variable(*e)?;
    }
    let ciphertexts = [V::ScalarField::from(0u64); CIPHERTEXT_LEN];
    for c in ciphertexts.iter() {
        circuit.create_public_variable(*c)?;
    }
    Ok(circuit)
}

#[client_circuit]
pub fn generate_keys<P, V, VSW, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: CircuitInputs<P, C, N, D>,
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
    let mut circuit = mint_circuit::<P, V, C, N, D>(circuit_inputs)?;
    circuit.finalize_for_arithmetization()?;

    let srs_size = circuit.srs_size()?;
    let mut rng = ChaChaRng::from_entropy();
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;

    let (pk, vk) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit)?;
    Ok((pk, vk))
}

fn check_params<P, V, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: &CircuitInputs<P, C, N, D>,
) -> Result<(), CircuitError>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
    V: Pairing<ScalarField = P::BaseField>,
{
    fn check_length(
        field_name: &str,
        actual_len: usize,
        expected_len: usize,
    ) -> Result<(), CircuitError> {
        if actual_len != expected_len {
            Err(CircuitError::ParameterError(format!(
                "Incorrect length for {field_name}. Expected {expected_len}, Obtained {actual_len}"
            )))
        } else {
            Ok(())
        }
    }

    // Check all fields with their respective expected lengths
    check_length("token_values", circuit_inputs.token_values.len(), C)?;
    check_length("token_salts", circuit_inputs.token_salts.len(), C)?;
    check_length("token_ids", circuit_inputs.token_ids.len(), C)?;
    check_length("recipients", circuit_inputs.recipients.len(), C)?;

    Ok(())
}
#[cfg(test)]
mod test {
    use super::*;
    use common::crypto::poseidon::Poseidon;
    use curves::pallas::{Fq, Fr, PallasConfig};
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};

    #[test]
    fn test_new_mint_circuit() {
        MintCircuit::<VestaConfig>::new::<PallasConfig, _, 1>()
            .expect("New mint circuit should be created");
    }

    #[test]
    fn test_default_inputs() {
        let inputs = build_default_inputs::<PallasConfig, VestaConfig, _, 1, 0, 0>().unwrap();

        assert_eq!(inputs.token_values.len(), 1);
        assert_eq!(inputs.token_values[0], Fq::from(0u64));

        assert_eq!(inputs.token_ids.len(), 1);
        assert_eq!(inputs.token_ids[0], Fq::from(0u64));

        assert_eq!(inputs.token_salts.len(), 1);
        assert_eq!(inputs.token_salts[0], Fq::from(0u64));

        let pk = PrivateKey::<PallasConfig>::from_scalar(Fr::from(1u64));
        let public_key = PublicKey::from_private_key(&pk);

        assert_eq!(inputs.recipients.len(), 1);
        assert_eq!(inputs.recipients[0], public_key);
    }

    #[test]
    fn test_generate_keys() {
        let mint_circuit = MintCircuit::<VestaConfig>::new::<PallasConfig, _, 1>()
            .expect("New mint circuit should be created");

        let pk = mint_circuit.get_proving_key();
        let vk = mint_circuit.get_verifying_key();

        let mut inputs = build_default_inputs::<PallasConfig, VestaConfig, _, 1, 0, 0>().unwrap();
        inputs.token_values[0] = Fq::from(10u64);
        inputs.token_ids[0] = Fq::from(10u64);
        inputs.token_salts[0] = Fq::from(10u64);

        let (test_pk, test_vk) = mint_circuit
            .generate_keys(inputs)
            .expect("Should be able to generate new circuit keys");

        assert_eq!(vk, test_vk);
        assert_eq!(pk, test_pk);
    }

    #[test]
    fn mint_test_default_inputs() -> Result<(), CircuitError> {
        let mint_circuit = MintCircuit::<VestaConfig>::new::<PallasConfig, _, 1>()
            .expect("New mint circuit should be created");
        let inputs = build_default_inputs::<PallasConfig, VestaConfig, _, 1, 0, 0>().unwrap();

        let plonk_mint_circuit = mint_circuit
            .to_plonk_circuit(inputs.clone())
            .expect("To plonk circuit failed");

        let poseidon: Poseidon<Fq> = Poseidon::new();
        let public_commitment = poseidon
            .hash(vec![
                inputs.token_values[0],
                inputs.token_ids[0],
                inputs.token_salts[0],
                inputs.recipients[0].as_affine().x,
                inputs.recipients[0].as_affine().y,
            ])
            .unwrap();

        assert!(plonk_mint_circuit
            .check_circuit_satisfiability(&[
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                public_commitment,
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0)
            ])
            .is_ok());
        Ok(())
    }

    #[test]
    fn mint_test_inputs_from_builder() -> Result<(), CircuitError> {
        let value = Fq::from(1u64);
        let token_id = Fq::from(2u64);
        let token_nonce = Fq::from(3u64);
        let pk = PrivateKey::from_scalar(Fr::from(1u64));
        let token_owner = PublicKey::from_private_key(&pk);

        let mut circuit_inputs_builder = CircuitInputs::<PallasConfig, 1, 0, 0>::new();

        let circuit_inputs = circuit_inputs_builder
            .add_token_values(vec![Fq::from(value)])
            .add_token_ids(vec![Fq::from(token_id)])
            .add_token_salts(vec![Fq::from(token_nonce)])
            .add_recipients(vec![token_owner])
            .build();

        let mint_circuit = MintCircuit::<VestaConfig>::new::<PallasConfig, _, 1>()
            .expect("New mint circuit should be created");

        let plonk_mint_circuit = mint_circuit
            .to_plonk_circuit(circuit_inputs)
            .expect("To plonk circuit failed");

        let poseidon: Poseidon<Fq> = Poseidon::new();
        let public_commitment = poseidon
            .hash(vec![
                value,
                token_id,
                token_nonce,
                token_owner.as_affine().x,
                token_owner.as_affine().y,
            ])
            .unwrap();

        assert!(plonk_mint_circuit
            .check_circuit_satisfiability(&[
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                public_commitment,
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0)
            ])
            .is_ok());
        Ok(())
    }
}
