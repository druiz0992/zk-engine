use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::PrimeField;

use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

use super::constants::*;
use crate::client::circuits::circuit_inputs::CircuitInputs;
use crate::primitives::circuits::{
    kem_dem::{KemDemGadget, KemDemParams, PlainTextVars},
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};
use common::derived_keys::{NULLIFIER_PREFIX, PRIVATE_KEY_PREFIX};
use std::str::FromStr;

pub fn transfer_circuit<P, V, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: CircuitInputs<P>,
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
where
    P: SWCurveConfig,
    V: Pairing<ScalarField = P::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + KemDemParams<Field = V::ScalarField>,
{
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    // Swap_field = false
    circuit.create_public_boolean_variable(false)?;

    let private_key_domain = P::BaseField::from_str(PRIVATE_KEY_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;
    let nullifier_key_domain = P::BaseField::from_str(NULLIFIER_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;
    // Derive Keys - ToDo, remove this once we have HSM-compatible key derivation
    let private_key_domain_var = circuit.create_constant_variable(private_key_domain)?;
    let nullifier_key_domain_var = circuit.create_constant_variable(nullifier_key_domain)?;
    let root_key_var = circuit.create_variable(circuit_inputs.root_key)?;

    let private_key_var = PoseidonGadget::<
        PoseidonStateVar<POSEIDON_STATE_VAR_LEN3>,
        V::ScalarField,
    >::hash(&mut circuit, &[root_key_var, private_key_domain_var])?;
    let private_key_bits_var =
        circuit.unpack(private_key_var, V::ScalarField::MODULUS_BIT_SIZE as usize)?;

    let private_key_var_trunc = private_key_bits_var
        .into_iter()
        .take(PRIVATE_KEY_LEN)
        .collect::<Vec<_>>();

    let private_key_var_trunc_bits = private_key_var_trunc.as_slice();
    let generator_point_var = &circuit.create_constant_sw_point_variable(P::GENERATOR.into())?;

    // Implicit mod being done here
    let public_key_var = circuit
        .variable_base_binary_sw_scalar_mul::<P>(private_key_var_trunc_bits, generator_point_var)?;

    let nullifier_key_var = PoseidonGadget::<
        PoseidonStateVar<POSEIDON_STATE_VAR_LEN3>,
        V::ScalarField,
    >::hash(&mut circuit, &[root_key_var, nullifier_key_domain_var])?;

    // Check conservation of value
    // That is, sum of nullifiers = sum of commitments
    let old_commitment_values_vars = circuit_inputs
        .old_token_values
        .iter()
        .map(|v| circuit.create_variable(*v))
        .collect::<Result<Vec<_>, _>>()?;
    let commitment_values_vars = circuit_inputs
        .token_values
        .iter()
        .map(|v| circuit.create_variable(*v))
        .collect::<Result<Vec<_>, _>>()?;

    let nullifiers_sum_var = old_commitment_values_vars
        .iter()
        .try_fold(circuit.zero(), |acc, v| circuit.add(acc, *v))?;

    let commitment_sum_var = commitment_values_vars
        .iter()
        .try_fold(circuit.zero(), |acc, v| circuit.add(acc, *v))?;

    circuit.enforce_equal(nullifiers_sum_var, commitment_sum_var)?;

    // Calculate the private old commitment hash and check the sibling path
    // Calculate the public nullifier hash
    let token_id_var = circuit.create_variable(circuit_inputs.token_ids[0])?;
    // TODO public input can be a hash of old roots, to be re-calc'd in base circuit
    let commitment_roots_vars = circuit_inputs
        .commitment_tree_root
        .iter()
        .map(|r| circuit.create_public_variable(*r).unwrap())
        .collect::<Vec<_>>();
    for (i, &old_commitment_val_var) in old_commitment_values_vars.iter().enumerate() {
        let old_commitment_nonce_var =
            circuit.create_variable(circuit_inputs.old_token_salts[i])?;
        let old_commitment_hash_var =
            PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
                &mut circuit,
                &[
                    old_commitment_val_var,
                    token_id_var,
                    old_commitment_nonce_var,
                    public_key_var.get_x(),
                    public_key_var.get_y(),
                ],
            )?;
        // Check the sibling path
        let commitment_root_var = commitment_roots_vars[i];
        let calc_commitment_root_var = BinaryMerkleTreeGadget::<D, V::ScalarField>::calculate_root(
            &mut circuit,
            old_commitment_hash_var,
            circuit_inputs.membership_path_index[i],
            circuit_inputs.membership_path[i]
                .clone()
                .try_into()
                .map_err(|_| {
                    CircuitError::ParameterError("Error converting membership path".to_string())
                })?,
        )?;
        circuit.enforce_equal(calc_commitment_root_var, commitment_root_var)?;

        let nullifier_hash_var =
            PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN3>, V::ScalarField>::hash(
                &mut circuit,
                &[nullifier_key_var, old_commitment_hash_var],
            )?;
        circuit.set_variable_public(nullifier_hash_var)?;
    }

    // Calculate the recipients(first) commitment hash, this has an additional requirement
    // Check that the first commitment nonce is the same as the index of the first commitment
    // Check that the recipients public key is set as the new owner
    let recipient_commitment_nonce_var = circuit.create_variable(circuit_inputs.token_salts[0])?;
    let index_of_first_commitment_var =
        circuit.create_variable(circuit_inputs.membership_path_index[0])?;
    circuit.enforce_equal(
        recipient_commitment_nonce_var,
        index_of_first_commitment_var,
    )?;

    let recipient_var =
        circuit.create_sw_point_variable(circuit_inputs.recipients[0].as_affine().into())?;
    let recipient_commitment_hash_var =
        PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
            &mut circuit,
            &[
                commitment_values_vars[0],
                token_id_var,
                recipient_commitment_nonce_var,
                recipient_var.get_x(),
                recipient_var.get_y(),
            ],
        )?;
    circuit.set_variable_public(recipient_commitment_hash_var)?;

    // Calculate the remaining change commitment hashes ()
    // The recipients of these commitments are the same as the sender
    // TODO set to one (and => C < 3 always) as no reason to send yourself multiple change commitments
    // TODO don't provide the change commit value, calc it in circuit

    #[allow(clippy::needless_range_loop)]
    for i in 1..C {
        let commitment_nonce_var = circuit.create_variable(circuit_inputs.token_salts[i])?;
        let commitment_hash_var =
            PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
                &mut circuit,
                &[
                    commitment_values_vars[i],
                    token_id_var,
                    commitment_nonce_var,
                    public_key_var.get_x(),
                    public_key_var.get_y(),
                ],
            )?;
        circuit.set_variable_public(commitment_hash_var)?;
    }
    // Check the encryption of secret information to the recipient
    // This proves that they will be able to decrypt the information
    let gen = circuit.create_constant_sw_point_variable(P::GENERATOR.into())?;
    let ephemeral_key_var = circuit.create_variable(circuit_inputs.ephemeral_key)?;
    let eph_key_bits =
        circuit.unpack(ephemeral_key_var, P::BaseField::MODULUS_BIT_SIZE as usize)?;
    let eph_public_key = circuit.variable_base_binary_sw_scalar_mul::<P>(&eph_key_bits, &gen)?;
    circuit.set_variable_public(eph_public_key.get_x())?;
    circuit.set_variable_public(eph_public_key.get_y())?;

    let ciphertext_vars =
        KemDemGadget::<PlainTextVars<PLAINTEXT_VAR_LEN>, P, V::ScalarField>::kem_dem(
            &mut circuit,
            ephemeral_key_var,
            recipient_var,
            [
                commitment_values_vars[0],
                token_id_var,
                recipient_commitment_nonce_var,
            ],
        )?;
    for ciphertext in ciphertext_vars {
        circuit.set_variable_public(ciphertext)?;
    }
    circuit.check_circuit_satisfiability(&circuit.public_input()?)?;
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}
