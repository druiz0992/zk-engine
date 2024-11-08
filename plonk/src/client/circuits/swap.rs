use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

use crate::primitives::circuits::{
    kem_dem::{KemDemGadget, KemDemParams, PlainTextVars},
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};

// D: depth of the merkle tree
#[allow(clippy::too_many_arguments)]
pub fn swap_circuit<E, P, const D: usize>(
    old_commitment_value: P::ScalarField,
    old_commitment_nonce: P::ScalarField,
    old_commitment_sibling_path: [P::ScalarField; D],
    old_commitment_leaf_index: P::ScalarField,
    commitment_tree_root: P::ScalarField,
    outgoing_token_id: P::ScalarField,
    incoming_commitment_value: P::ScalarField,
    incoming_commitment_nonce: P::ScalarField,
    incoming_token_id: P::ScalarField,
    recipient: Affine<E>,
    root_key: P::ScalarField,
    ephemeral_key: P::ScalarField,
    private_key_domain: P::ScalarField, // Remove this later as can be constant
    nullifier_key_domain: P::ScalarField, // Remove this later as can be constant
) -> Result<PlonkCircuit<P::ScalarField>, CircuitError>
where
    E: SWCurveConfig,
    P: Pairing<ScalarField = E::BaseField>,
    <E as CurveConfig>::BaseField: PrimeField + KemDemParams<Field = P::ScalarField>,
{
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    // Swap_field = true
    circuit.create_public_boolean_variable(true)?;

    // Derive Keys - ToDo, remove this once we have HSM-compatible key derivation
    let private_key_domain_var = circuit.create_constant_variable(private_key_domain)?;
    let nullifier_key_domain_var = circuit.create_constant_variable(nullifier_key_domain)?;
    let root_key_var = circuit.create_variable(root_key)?;

    let private_key_var = PoseidonGadget::<PoseidonStateVar<3>, P::ScalarField>::hash(
        &mut circuit,
        &[root_key_var, private_key_domain_var],
    )?;
    let private_key_bits_var =
        circuit.unpack(private_key_var, P::ScalarField::MODULUS_BIT_SIZE as usize)?;

    let private_key_var_trunc = private_key_bits_var
        .into_iter()
        .take(248)
        .collect::<Vec<_>>();

    let private_key_var_trunc_bits = private_key_var_trunc.as_slice();
    let generator_point_var = &circuit.create_constant_sw_point_variable(E::GENERATOR.into())?;

    // Implicit mod being done here
    let public_key_var = circuit
        .variable_base_binary_sw_scalar_mul::<E>(private_key_var_trunc_bits, generator_point_var)?;

    let nullifier_key_var = PoseidonGadget::<PoseidonStateVar<3>, P::ScalarField>::hash(
        &mut circuit,
        &[root_key_var, nullifier_key_domain_var],
    )?;

    // Calculate the private old commitment hash and check the sibling path
    let outgoing_token_id_var = circuit.create_variable(outgoing_token_id)?;
    let commitment_root_var = circuit
        .create_public_variable(commitment_tree_root)
        .unwrap();
    let old_commitment_nonce_var = circuit.create_variable(old_commitment_nonce)?;
    let old_commitment_val_var = circuit.create_variable(old_commitment_value)?;

    let old_commitment_hash_var = PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
        &mut circuit,
        &[
            old_commitment_val_var,
            outgoing_token_id_var,
            old_commitment_nonce_var,
            public_key_var.get_x(),
            public_key_var.get_y(),
        ],
    )?;
    // Check the sibling path
    let calc_commitment_root_var = BinaryMerkleTreeGadget::<D, P::ScalarField>::calculate_root(
        &mut circuit,
        old_commitment_hash_var,
        old_commitment_leaf_index,
        old_commitment_sibling_path,
    )?;
    circuit.enforce_equal(calc_commitment_root_var, commitment_root_var)?;
    // Calculate the public nullifier hash
    let nullifier_hash_var = PoseidonGadget::<PoseidonStateVar<3>, P::ScalarField>::hash(
        &mut circuit,
        &[nullifier_key_var, old_commitment_hash_var],
    )?;
    circuit.set_variable_public(nullifier_hash_var)?;

    // Calculate the recipients commitment hash, this has an additional requirement
    // Check that the first commitment nonce is the same as the index of the first commitment
    // Check that the recipients public key is set as the new owner
    let recipient_commitment_nonce_var = circuit.create_variable(old_commitment_leaf_index)?;
    let recipient_var = circuit.create_sw_point_variable(recipient.into())?;
    // We are sending the exact token => same value
    let new_commitment_val_var = circuit.create_variable(old_commitment_value)?;
    let recipient_commitment_hash_var =
        PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
            &mut circuit,
            &[
                new_commitment_val_var,
                outgoing_token_id_var,
                recipient_commitment_nonce_var,
                recipient_var.get_x(),
                recipient_var.get_y(),
            ],
        )?;
    circuit.set_variable_public(recipient_commitment_hash_var)?;

    // Calculate the expected incoming commitment as agreed in the swap
    let incoming_token_id_var = circuit.create_variable(incoming_token_id)?;
    let incoming_commitment_nonce_var = circuit.create_variable(incoming_commitment_nonce)?;
    let incoming_commitment_val_var = circuit.create_variable(incoming_commitment_value)?;

    let incoming_commitment_hash_var = PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
        &mut circuit,
        &[
            incoming_commitment_val_var,
            incoming_token_id_var,
            incoming_commitment_nonce_var,
            public_key_var.get_x(),
            public_key_var.get_y(),
        ],
    )?;

    circuit.set_variable_public(incoming_commitment_hash_var)?;

    // Check the encryption of secret information to the recipient
    // This proves that they will be able to decrypt the information
    let gen = circuit.create_constant_sw_point_variable(E::GENERATOR.into())?;
    let ephemeral_key_var = circuit.create_variable(ephemeral_key)?;
    let eph_key_bits =
        circuit.unpack(ephemeral_key_var, E::BaseField::MODULUS_BIT_SIZE as usize)?;
    let eph_public_key = circuit.variable_base_binary_sw_scalar_mul::<E>(&eph_key_bits, &gen)?;
    circuit.set_variable_public(eph_public_key.get_x())?;
    circuit.set_variable_public(eph_public_key.get_y())?;

    // TODO do we need this for swap?
    let ciphertext_vars = KemDemGadget::<PlainTextVars<3>, E, P::ScalarField>::kem_dem(
        &mut circuit,
        ephemeral_key_var,
        recipient_var,
        [
            new_commitment_val_var,
            outgoing_token_id_var,
            recipient_commitment_nonce_var,
        ],
    )?;
    for ciphertext in ciphertext_vars {
        circuit.set_variable_public(ciphertext)?;
    }

    Ok(circuit)
}

#[cfg(test)]
mod test {
    use ark_ec::{short_weierstrass::SWCurveConfig, CurveGroup};
    use ark_std::UniformRand;
    use common::crypto::poseidon::Poseidon;
    use curves::{
        pallas::{Affine, Fq, Fr, PallasConfig},
        vesta::VestaConfig,
    };
    use jf_relation::{errors::CircuitError, Circuit};
    use jf_utils::{fq_to_fr_with_mask, test_rng};
    use std::str::FromStr;
    use trees::{
        membership_tree::{MembershipTree, Tree},
        tree::AppendTree,
    };
    #[test]
    fn swap_test() -> Result<(), CircuitError> {
        swap_test_helper()
    }

    fn swap_test_helper() -> Result<(), CircuitError> {
        let root_key = Fq::rand(&mut test_rng());
        let private_key_domain = Fq::from_str("1").unwrap();
        let nullifier_key_domain = Fq::from_str("2").unwrap();
        let private_key: Fq = Poseidon::<Fq>::new()
            .hash(vec![root_key, private_key_domain])
            .unwrap();
        let private_key_trunc: Fr = fq_to_fr_with_mask(&private_key);

        let token_owner = (PallasConfig::GENERATOR * private_key_trunc).into_affine();

        let outgoing_token_id = Fq::from(2 as u32);
        let incoming_token_id = Fq::from(3 as u32);

        let outgoing_value = Fq::from(20 as u32);
        let outgoing_nonce = Fq::from(4 as u32);
        let old_commitment_hash = Poseidon::<Fq>::new()
            .hash(vec![
                outgoing_value,
                outgoing_token_id,
                outgoing_nonce,
                token_owner.x,
                token_owner.y,
            ])
            .unwrap();

        let recipient_public_key = Affine::rand(&mut test_rng());
        let incoming_value = Fq::from(10 as u32);
        let incoming_nonce = Fq::from(5 as u32);
        let incoming_commitment_hash = Poseidon::<Fq>::new()
            .hash(vec![
                incoming_value,
                incoming_token_id,
                incoming_nonce,
                token_owner.x,
                token_owner.y,
            ])
            .unwrap();
        let comm_tree: Tree<Fq, 8> = Tree::from_leaves(vec![old_commitment_hash]);
        let old_comm_path: [Fq; 8] = comm_tree.membership_witness(0).unwrap().try_into().unwrap();

        let expected_new_commitment_hash = Poseidon::<Fq>::new()
            .hash(vec![
                outgoing_value,
                outgoing_token_id,
                Fq::from(0 as u32), // index of old commitment
                recipient_public_key.x,
                recipient_public_key.y,
            ])
            .unwrap();

        let ephemeral_key = Fq::rand(&mut test_rng());

        let circuit = super::swap_circuit::<PallasConfig, VestaConfig, 8>(
            outgoing_value,
            outgoing_nonce,
            old_comm_path,
            Fq::from(0 as u32),
            comm_tree.root(),
            outgoing_token_id,
            incoming_value,
            incoming_nonce,
            incoming_token_id,
            recipient_public_key,
            root_key,
            ephemeral_key,
            private_key_domain,
            nullifier_key_domain,
        )?;

        let public_inputs = circuit.public_input()?;
        assert!(expected_new_commitment_hash == public_inputs[3]);
        assert!(incoming_commitment_hash == public_inputs[4]);
        assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());
        Ok(())
    }
}
