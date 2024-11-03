use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;

use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::{errors::CircuitError, PlonkCircuit};

use super::circuit_inputs::CircuitInputs;
use crate::client::ClientPlonkCircuit;
use crate::primitives::circuits::kem_dem::KemDemParams;
use common::crypto::poseidon::constants::PoseidonParams;
use macros::client_circuit;

pub mod circuit;
mod constants;
pub mod utils;

pub use circuit::transfer_circuit;
pub use utils::build_random_inputs;

pub struct TransferCircuit;

impl TransferCircuit {
    pub fn new() -> Self {
        TransferCircuit
    }
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self::new()
    }
}

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize>
    ClientPlonkCircuit<P, V, VSW, C, N, D> for TransferCircuit
{
    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
        transfer_circuit::<P, V, C, N, D>(circuit_inputs)
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
    check_length("token_ids", circuit_inputs.token_ids.len(), 1)?;
    check_length("old_token_values", circuit_inputs.old_token_values.len(), N)?;
    check_length("old_token_salts", circuit_inputs.old_token_salts.len(), N)?;
    check_length(
        "commitment_tree_root",
        circuit_inputs.commitment_tree_root.len(),
        N,
    )?;
    check_length(
        "membership_path_index",
        circuit_inputs.membership_path_index.len(),
        N,
    )?;
    check_length("membership_path", circuit_inputs.membership_path.len(), N)?;
    check_length("recipients", circuit_inputs.recipients.len(), 1)?;

    if !circuit_inputs
        .membership_path
        .iter()
        .all(|inner_vec| inner_vec.path_len() == D)
    {
        return Err(CircuitError::ParameterError(format!(
            "Incorrect length for membership_path elements. Expected {D}",
        )));
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};

    use crate::client as plonk_client;
    #[test]
    fn test_new_transfer_circuit() {
        TransferCircuit::new();
    }

    #[test]
    fn test_generate_keys() {
        generate_keys_helper::<1, 1, 8>();
        generate_keys_helper::<2, 2, 8>();
        generate_keys_helper::<1, 2, 8>();
        generate_keys_helper::<2, 5, 8>();
    }

    fn generate_keys_helper<const C: usize, const N: usize, const D: usize>() {
        let circuit = TransferCircuit::new();
        let inputs =
            utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(&format!(
                "Error generating random inputs for transfer circuit with C:{C}, N:{N}, D:{D}"
            ));
        plonk_client::generate_keys_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            &circuit, inputs,
        )
        .expect(&format!(
            "Error generating key for transfer circuit from random inputs with C:{C}, N:{N}, D:{D}"
        ));
    }

    #[test]
    fn transfer_test() -> Result<(), CircuitError> {
        transfer_test_helper::<1, 1, 8>()?;
        transfer_test_helper::<2, 2, 8>()?;
        transfer_test_helper::<1, 2, 8>()?;
        transfer_test_helper::<2, 5, 8>()
    }

    fn transfer_test_helper<const C: usize, const N: usize, const D: usize>(
    ) -> Result<(), CircuitError> {
        let inputs =
            utils::build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>().expect(&format!(
                "Error generating random inputs for transfer circuit with C:{C}, N:{N}, D:{D}"
            ));
        let transfer_circuit = TransferCircuit::new();

        let plonk_circuit =
            plonk_client::build_plonk_circuit_from_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
                &transfer_circuit,
                inputs.clone(),
            )
            .expect(&format!(
                "Error building plonk mint circuit from transfer inputs with C:{C}, N:{N}, D:{D}"
            ));

        assert!(plonk_circuit
            .check_circuit_satisfiability(&plonk_circuit.public_input().unwrap())
            .is_ok());
        Ok(())
    }
}
