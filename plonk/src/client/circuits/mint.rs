use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    constraint_system::PlonkCircuit, errors::CircuitError, gadgets::ecc::SWToTEConParam,
};

use super::structs::CircuitId;
use crate::{
    client::circuits::circuit_inputs::CircuitInputs, client::ClientPlonkCircuit,
    primitives::circuits::kem_dem::KemDemParams,
};
use common::crypto::poseidon::constants::PoseidonParams;
use macros::client_circuit;

pub mod circuit;
mod constants;
pub mod utils;

pub use circuit::*;
pub use utils::build_random_inputs;

pub struct MintCircuit;

impl MintCircuit {
    const CIRCUIT_ID: &'static str = "MINT";

    pub fn new() -> Self {
        MintCircuit
    }
    pub fn circuit_id() -> CircuitId {
        CircuitId::new(MintCircuit::CIRCUIT_ID)
    }
}

impl Default for MintCircuit {
    fn default() -> Self {
        Self::new()
    }
}

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize>
    ClientPlonkCircuit<P, V, VSW, C, N, D> for MintCircuit
{
    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
        mint_circuit::<P, V, VSW, C, N, D>(circuit_inputs)
    }
}

fn check_inputs<P, V, const C: usize, const N: usize, const D: usize>(
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
    use crate::client as plonk_client;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};

    #[test]
    fn test_new_mint_circuit() {
        MintCircuit::new();
    }

    #[test]
    fn test_generate_keys() {
        generate_keys_helper::<1, 0, 0>();
        generate_keys_helper::<4, 0, 0>();
    }

    fn generate_keys_helper<const C: usize, const N: usize, const D: usize>() {
        let mint_circuit = MintCircuit::new();
        let inputs = utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(
            &format!("Error generating random inputs for mint circuit with C:{C}, N:{N}, D:{D}"),
        );
        plonk_client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            &mint_circuit,
            inputs,
        )
        .expect(&format!(
            "Error generating key for mint circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));
    }

    #[test]
    fn mint_test() -> Result<(), CircuitError> {
        mint_test_helper_random::<1, 0, 0>()?;
        mint_test_helper_random::<4, 0, 0>()
    }

    fn mint_test_helper_random<const C: usize, const N: usize, const D: usize>(
    ) -> Result<(), CircuitError> {
        let inputs = utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(
            &format!("Error generating random inputs for mint circuit with C:{C}, N:{N}, D:{D}"),
        );
        let mint_circuit = MintCircuit::new();

        let plonk_circuit =
            plonk_client::build_plonk_circuit_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
                &mint_circuit,
                inputs.clone(),
            )
            .expect(&format!(
                "Error building plonk mint circuit from random inputs with C:{C}, N:{N}, D:{D}"
            ));

        assert!(plonk_circuit
            .check_circuit_satisfiability(&plonk_circuit.public_input().unwrap())
            .is_ok());

        Ok(())
    }
}
