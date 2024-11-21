use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;

use super::circuit_inputs::CircuitInputs;
use crate::client::structs::ClientPubInputs;
use crate::client::ClientPlonkCircuit;
use crate::primitives::circuits::kem_dem::KemDemParams;
use crate::rollup::circuits::client_input::LowNullifierInfo;
use crate::rollup::circuits::client_input::{self, ClientInput};
use common::crypto::poseidon::constants::PoseidonParams;
use common::structs::CircuitType;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use jf_relation::{errors::CircuitError, PlonkCircuit};
use trees::IndexedMerkleTree;
use zk_macros::client_bounds;

pub mod circuit;
mod constants;
pub mod utils;

pub use circuit::transfer_circuit;
pub use constants::*;
pub use utils::build_random_inputs;

#[derive(Debug, Hash)]
pub struct TransferCircuit<const C: usize, const N: usize, const D: usize>;

impl<const C: usize, const N: usize, const D: usize> TransferCircuit<C, N, D> {
    pub fn new() -> Self {
        TransferCircuit
    }
    pub fn get_circuit_type(&self) -> CircuitType {
        get_circuit_type_from_params(C, N)
    }
    #[client_bounds]
    pub fn as_circuit<P, V, VSW>(self) -> Box<dyn ClientPlonkCircuit<P, V, VSW>> {
        Box::new(self)
    }
}

pub fn get_circuit_type_from_params(c: usize, n: usize) -> CircuitType {
    CircuitType::Transfer(c, n)
}

impl<const C: usize, const N: usize, const D: usize> Default for TransferCircuit<C, N, D> {
    fn default() -> Self {
        Self::new()
    }
}

#[client_bounds]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize> ClientPlonkCircuit<P, V, VSW>
    for TransferCircuit<C, N, D>
{
    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
        transfer_circuit::<P, V, C, N, D>(circuit_inputs)
    }
    fn generate_random_inputs(
        &self,
        token_id: Option<V::ScalarField>,
    ) -> Result<CircuitInputs<P>, CircuitError> {
        utils::build_random_inputs::<P, V, VSW, C, N, D>(token_id)
    }
    fn get_circuit_type(&self) -> CircuitType {
        self.get_circuit_type()
    }
    fn get_commitment_and_nullifier_count(&self) -> (usize, usize) {
        (C, N)
    }

    fn generate_sequencer_inputs(
        &self,
        proof: Proof<V>,
        vk: VerifyingKey<V>,
        public_inputs: &ClientPubInputs<V::ScalarField>,
        low_nullifier_info: &Option<LowNullifierInfo<V, 32>>,
    ) -> ClientInput<V> {
        let (c, n) =
            <TransferCircuit<C, N, D> as ClientPlonkCircuit<P, V, VSW>>::get_commitment_and_nullifier_count(
                self,
            );
        let mut client_input = ClientInput::<V>::new(proof, vk, c, n);

        client_input
            .set_nullifiers(&public_inputs.nullifiers)
            .set_commitments(&public_inputs.commitments)
            .set_commitment_tree_root(&public_inputs.commitment_root)
            .set_eph_pub_key(
                client_input::to_eph_key_array::<V>(public_inputs.ephemeral_public_key.clone())
                    .unwrap(),
            )
            .set_ciphertext(
                client_input::to_ciphertext_array::<V>(public_inputs.ciphertexts.clone()).unwrap(),
            );

        if let Some(info) = low_nullifier_info {
            client_input.set_low_nullifier_info(info);
        }
        client_input
    }
}

fn check_inputs<P, V, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: &CircuitInputs<P>,
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

    if C > MAX_N_COMMITMENTS {
        return Err(CircuitError::ParameterError(format!("Incorrect number of commitments C in transfer circuit. Maximum C: {MAX_N_COMMITMENTS}, Obtained: {C}")));
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
    use crate::client::PlonkCircuitParams;

    use super::*;
    use curves::pallas::PallasConfig;
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};

    #[test]
    fn test_new_transfer_circuit() {
        TransferCircuit::<2, 4, 8>::new();
    }

    #[test]
    fn test_generate_keys() {
        generate_keys_helper::<1, 1, 8>();
        generate_keys_helper::<2, 2, 8>();
        generate_keys_helper::<1, 2, 8>();
        generate_keys_helper::<2, 5, 8>();
    }

    fn generate_keys_helper<const C: usize, const N: usize, const D: usize>() {
        let circuit =
            TransferCircuit::<C, N, D>::new().as_circuit::<PallasConfig, VestaConfig, _>();
        circuit.generate_keys().expect(&format!(
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
        let inputs = build_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>(None).unwrap();
        let transfer_circuit = TransferCircuit::<C, N, D>::new()
            .as_circuit::<PallasConfig, VestaConfig, _>()
            .to_plonk_circuit(inputs)
            .unwrap();

        assert!(transfer_circuit
            .check_circuit_satisfiability(&transfer_circuit.public_input().unwrap())
            .is_ok());
        Ok(())
    }
}
