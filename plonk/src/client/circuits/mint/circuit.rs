use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    constraint_system::PlonkCircuit, errors::CircuitError, gadgets::ecc::SWToTEConParam, Circuit,
};

use super::constants::*;
use crate::{
    client::circuits::circuit_inputs::CircuitInputs,
    primitives::circuits::{
        kem_dem::KemDemParams,
        poseidon::{PoseidonGadget, PoseidonStateVar},
    },
};
use common::crypto::poseidon::constants::PoseidonParams;
use macros::client_circuit;

#[client_circuit]
pub fn mint_circuit<P, V, VSW, const C: usize>(
    circuit_inputs: CircuitInputs<P>,
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError> {
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
    circuit.check_circuit_satisfiability(&circuit.public_input()?)?;
    circuit.finalize_for_arithmetization()?;

    Ok(circuit)
}
