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

// N: number of nullifiers
// C: number of commitments
// D: depth of the merkle tree
#[allow(clippy::too_many_arguments)]
pub fn transfer_circuit<E, P, const N: usize, const C: usize, const D: usize>(
    old_commitment_values: [P::ScalarField; N],
    old_commitment_nonces: [P::ScalarField; N],
    old_commitment_sibling_path: [[P::ScalarField; D]; N],
    old_commitment_leaf_index: [P::ScalarField; N],
    commitment_tree_root: [P::ScalarField; N],
    commitment_values: [P::ScalarField; C],
    commitment_nonces: [P::ScalarField; C], // The first one of this must be the old_commitment_leaf_index
    token_id: P::ScalarField,
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

    // Check conservation of value
    // That is, sum of nullifiers = sum of commitments
    let old_commitment_values_vars = old_commitment_values
        .iter()
        .map(|v| circuit.create_variable(*v))
        .collect::<Result<Vec<_>, _>>()?;
    let commitment_values_vars = commitment_values
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
    let token_id_var = circuit.create_variable(token_id)?;
    // TODO public input can be a hash of old roots, to be re-calc'd in base circuit
    let commitment_roots_vars = commitment_tree_root.iter().map(|r| circuit.create_public_variable(*r).unwrap()).collect::<Vec<_>>();
    for (i, &old_commitment_val_var) in old_commitment_values_vars.iter().enumerate() {
        let old_commitment_nonce_var = circuit.create_variable(old_commitment_nonces[i])?;
        let old_commitment_hash_var = PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
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
        let calc_commitment_root_var =
            BinaryMerkleTreeGadget::<D, P::ScalarField>::calculate_root(
                &mut circuit,
                old_commitment_hash_var,
                old_commitment_leaf_index[i],
                old_commitment_sibling_path[i],
            )?;
        circuit.enforce_equal(calc_commitment_root_var, commitment_root_var)?;

        let nullifier_hash_var = PoseidonGadget::<PoseidonStateVar<3>, P::ScalarField>::hash(
            &mut circuit,
            &[nullifier_key_var, old_commitment_hash_var],
        )?;
        circuit.set_variable_public(nullifier_hash_var)?;
    }

    // Calculate the recipients(first) commitment hash, this has an additional requirement
    // Check that the first commitment nonce is the same as the index of the first commitment
    // Check that the recipients public key is set as the new owner
    let recipient_commitment_nonce_var = circuit.create_variable(commitment_nonces[0])?;
    let index_of_first_commitment_var = circuit.create_variable(old_commitment_leaf_index[0])?;
    circuit.enforce_equal(
        recipient_commitment_nonce_var,
        index_of_first_commitment_var,
    )?;
    let recipient_var = circuit.create_sw_point_variable(recipient.into())?;
    let recipient_commitment_hash_var =
        PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
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
    for i in 1..C {
        let commitment_nonce_var = circuit.create_variable(commitment_nonces[i])?;
        let commitment_hash_var = PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
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
    let gen = circuit.create_constant_sw_point_variable(E::GENERATOR.into())?;
    let ephemeral_key_var = circuit.create_variable(ephemeral_key)?;
    let eph_key_bits = circuit.unpack(ephemeral_key_var, E::BaseField::MODULUS_BIT_SIZE as usize)?;
    let eph_public_key = circuit.variable_base_binary_sw_scalar_mul::<E>(&eph_key_bits, &gen)?;
    circuit.set_variable_public(eph_public_key.get_x())?;
    circuit.set_variable_public(eph_public_key.get_y())?;

    let ciphertext_vars = KemDemGadget::<PlainTextVars<3>, E, P::ScalarField>::kem_dem(
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
    use trees::{membership_tree::{MembershipTree, Tree}, tree::AppendTree};
    use std::str::FromStr;
    #[test]
    fn transfer_test() -> Result<(), CircuitError> {
        transfer_test_helper::<1, 1>()?;
        transfer_test_helper::<2, 2>()?;
        transfer_test_helper::<2, 1>()?;
        transfer_test_helper::<5, 2>()
    }

    fn transfer_test_helper<const N: usize, const C: usize>() -> Result<(), CircuitError> {
        let root_key = Fq::rand(&mut test_rng());
        let private_key_domain = Fq::from_str("1").unwrap();
        let nullifier_key_domain = Fq::from_str("2").unwrap();
        let private_key: Fq = Poseidon::<Fq>::new()
            .hash(vec![root_key, private_key_domain])
            .unwrap();
        let private_key_trunc: Fr = fq_to_fr_with_mask(&private_key);

        let token_owner = (PallasConfig::GENERATOR * private_key_trunc).into_affine();
        let token_id = Fq::from_str("2").unwrap();

        let mut values = vec![];
        let mut token_nonces = vec![];
        let mut old_commitment_hashes = vec![];
        let mut total_value = Fq::from(0 as u32);
        for j in 0..N {
            let value = Fq::from(j as u32 + 10);
            let token_nonce = Fq::from(j as u32 + 3);
            let old_commitment_hash = Poseidon::<Fq>::new()
            .hash(vec![
                value,
                token_id,
                token_nonce,
                token_owner.x,
                token_owner.y,
            ])
            .unwrap();
            values.push(value);
            token_nonces.push(token_nonce);
            old_commitment_hashes.push(old_commitment_hash);
            total_value += value;
        }

        let comm_tree: Tree<Fq, 8> = Tree::from_leaves(old_commitment_hashes);
        let mut old_comm_paths = [[Fq::from(0 as u32); 8]; N];
        for j in 0..N {
            old_comm_paths[j] = comm_tree.membership_witness(j).unwrap().try_into().unwrap();
        }

        let recipient_public_key = Affine::rand(&mut test_rng());
        let ephemeral_key = Fq::rand(&mut test_rng());

        let mut new_values = [Fq::from(0 as u32); C];
        if C > 1 {
            new_values[0] = total_value - Fq::from(1 as u32);
            new_values[1] = Fq::from(1 as u32);
        } else {
            new_values[0] = total_value;
        }

        let circuit = super::transfer_circuit::<PallasConfig, VestaConfig, N, C, 8>(
            values.try_into().unwrap(),
            token_nonces.try_into().unwrap(),
            old_comm_paths,
            ark_std::array::from_fn(|i| Fq::from(i as u32)),
            [comm_tree.root.0; N],
            new_values,
            ark_std::array::from_fn(|i| Fq::from(i as u32)), // = old leaf indicies,
            token_id,
            recipient_public_key,
            root_key,
            ephemeral_key,
            private_key_domain,
            nullifier_key_domain,
        )?;

        let public_inputs = circuit.public_input()?;
        assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());
        Ok(())
    }
}
