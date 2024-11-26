use crate::client::structs::ClientPubInput;
use crate::rollup::circuits::client_input::ClientInput;
use crate::rollup::circuits::client_input::LowNullifierInfo;
use crate::{
    client::circuits::circuit_inputs::CircuitInputs, client::ClientPlonkCircuit,
    primitives::circuits::kem_dem::KemDemParams,
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::CircuitType;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    constraint_system::PlonkCircuit, errors::CircuitError, gadgets::ecc::SWToTEConParam,
};
use zk_macros::client_bounds;

pub mod circuit;
pub mod constants;
pub mod utils;

pub use circuit::*;
pub use utils::build_random_inputs;

#[derive(Debug, Hash)]
pub struct MintCircuit<const C: usize>;

impl<const C: usize> MintCircuit<C> {
    pub fn new() -> Self {
        MintCircuit
    }

    pub fn get_circuit_type(&self) -> CircuitType {
        get_circuit_type_from_params(C, 0)
    }

    #[client_bounds]
    pub fn as_circuit<P, V, VSW>(self) -> Box<dyn ClientPlonkCircuit<P, V, VSW>> {
        Box::new(self)
    }
}

pub fn get_circuit_type_from_params(c: usize, _n: usize) -> CircuitType {
    CircuitType::Mint(c)
}

impl<const C: usize> Default for MintCircuit<C> {
    fn default() -> Self {
        Self::new()
    }
}

#[client_bounds]
impl<P, V, VSW, const C: usize> ClientPlonkCircuit<P, V, VSW> for MintCircuit<C> {
    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
        mint_circuit::<P, V, VSW, C>(circuit_inputs)
    }
    fn generate_random_inputs(
        &self,
        token_id: Option<V::ScalarField>,
    ) -> Result<CircuitInputs<P>, CircuitError> {
        utils::build_random_inputs::<P, V, VSW, C>(token_id)
    }
    fn get_circuit_type(&self) -> CircuitType {
        self.get_circuit_type()
    }
    fn get_commitment_and_nullifier_count(&self) -> (usize, usize) {
        (C, 1)
    }
    fn generate_client_input_for_sequencer(
        &self,
        proof: Proof<V>,
        vk: VerifyingKey<V>,
        public_inputs: &ClientPubInput<V::ScalarField>,
        _low_nullifier_info: &Option<LowNullifierInfo<V, 32>>,
    ) -> ClientInput<V> {
        let (c, n) =
            <MintCircuit<C> as ClientPlonkCircuit<P, V, VSW>>::get_commitment_and_nullifier_count(
                self,
            );
        let mut client_inputs = ClientInput::<V>::new(proof, vk, c, n);
        client_inputs.set_commitments(&public_inputs.commitments);
        client_inputs
    }
}

#[allow(non_snake_case)]
pub fn check_inputs<P, V>(circuit_inputs: &CircuitInputs<P>, C: usize) -> Result<(), CircuitError>
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
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};

    #[test]
    fn test_new_mint_circuit() {
        MintCircuit::<1>::new();
    }

    #[test]
    fn test_generate_keys() {
        generate_keys_helper::<1>();
        generate_keys_helper::<4>();
    }

    fn generate_keys_helper<const C: usize>() {
        let mint_circuit = MintCircuit::<C>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        mint_circuit.generate_keys().expect(&format!(
            "Error generating key for mint circuit from random inputs with C:{C}"
        ));
    }

    #[test]
    fn mint_test() -> Result<(), CircuitError> {
        mint_test_helper_random::<1>()?;
        mint_test_helper_random::<4>()
    }

    fn mint_test_helper_random<const C: usize>() -> Result<(), CircuitError> {
        let inputs = build_random_inputs::<PallasConfig, VestaConfig, _, C>(None).unwrap();
        let mint_circuit = MintCircuit::<C>::new()
            .as_circuit::<PallasConfig, VestaConfig, _>()
            .to_plonk_circuit(inputs)
            .unwrap();

        assert!(mint_circuit
            .check_circuit_satisfiability(&mint_circuit.public_input().unwrap())
            .is_ok());

        Ok(())
    }
}
