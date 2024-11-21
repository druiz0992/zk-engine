use crate::rollup::circuits::client_input::ClientInput;
use crate::{
    client::circuits::mint::constants::{CIPHERTEXT_LEN, EPHEMERAL_KEY_LEN},
    primitives::circuits::{
        merkle_tree::BinaryMerkleTreeGadget,
        poseidon::{PoseidonGadget, PoseidonStateVar},
    },
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{One, PrimeField};
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::{
    accumulation::{
        accumulation_structs::PCSInstance, circuit::gadgets::verify_accumulation_gadget_sw_native,
        prover::AccProver,
    },
    circuit::plonk_partial_verifier::PlonkIpaSWProofNativeVar,
    ipa_structs::CommitKey,
    UnivariateIpaPCS,
};
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{short_weierstrass::SWPoint, SWToTEConParam},
    Circuit, PlonkCircuit,
};
use jf_utils::{field_switching, fr_to_fq};

use super::base_helpers::*;

const VK_PATHS_LEN: usize = 8;
const MAX_N_BASE_TRANSACTIONS: usize = 8;
const MAX_N_COMMITMENTS: usize = 4;
const MAX_N_NULLIFIERS: usize = 4;

#[allow(non_snake_case)]
#[allow(clippy::type_complexity)]
pub fn base_rollup_circuit<C1, C2, const D: usize>(
    client_inputs: Vec<ClientInput<C1>>,
    global_vk_root: C2::ScalarField,
    global_nullifier_root: C2::ScalarField,
    global_nullifier_leaf_count: C2::ScalarField,
    global_commitment_root: C2::ScalarField,
    g_polys: Vec<DensePolynomial<C2::BaseField>>,
    commit_key: CommitKey<C1>,
) -> Result<
    (
        PlonkCircuit<C2::ScalarField>,
        DensePolynomial<C2::BaseField>,
    ),
    CircuitError,
>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
    <C1 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C2::ScalarField> + RescueParameter + SWToTEConParam,

    C2: Pairing<BaseField = C1::ScalarField, ScalarField = C1::BaseField>,
{
    let I = client_inputs.len();

    if I != g_polys.len() {
        return Err(CircuitError::ParameterError(
            "Number of client inputs doesnt match with number of of g_polys".to_string(),
        ));
    }

    if I == 0 || I % 2 == 1 || I > MAX_N_BASE_TRANSACTIONS {
        return Err(CircuitError::ParameterError(
            "Incorrect number of client inputs".to_string(),
        ));
    }

    let mut circuit = PlonkCircuit::new_ultra_plonk(8);
    let global_commitment_root_var = circuit.create_public_variable(global_commitment_root)?;
    let global_vk_root_var = circuit.create_public_variable(global_vk_root)?;
    // This is the mutated nullifier root that is validated against with each input
    let nullifier_new_root = circuit.create_public_variable(global_nullifier_root)?;
    // This is the mutated leaf_count that doubles as the insertion point
    let mut leaf_count = circuit.create_public_variable(global_nullifier_leaf_count)?;
    // This will hold the instances per PCS
    let mut instances = vec![];
    let mut g_comms_vars = vec![];
    let mut u_challenges_vars = vec![];
    // This will hold the commitment hashes from each input that is turned into a subtree
    let mut leaf_hashes = vec![];
    // This will hold nullifier leaf hashes from each input that is turned into a subtree
    let mut nullifier_leaf_hashes = vec![];
    // This will hold the swap_fields for each client proof
    let mut swap_vars = vec![];
    // This will hold the output commitments for each client proof (used in swap checks)
    let mut out_commitments = vec![];

    let mut prev_nullifier_low_nullifier =
        create_initial_low_nullifier_vars::<C1, 8>(&mut circuit, &client_inputs[0])?;

    // These values are hardcoded based on turbo_plonk vks
    for (input_idx, input) in client_inputs.iter().enumerate() {
        let N: usize = input.nullifiers.len();
        let C: usize = input.commitments.len();

        if N > MAX_N_NULLIFIERS {
            return Err(CircuitError::ParameterError(
                "Number of client nullifiers exceeds maximum".to_string(),
            ));
        }

        if C > MAX_N_COMMITMENTS {
            return Err(CircuitError::ParameterError(
                "Number of client commitments exceeds maximum".to_string(),
            ));
        }

        //----------------------------Step 1: Hash Verification Key ---------------------------------
        let (verifying_key_var, vk_var_hash) =
            hash_verification_key::<C1, C2, D>(&mut circuit, &input.vk)?;

        //------------------------------------------------------------------------------

        //----------------------------Step 2: Membership check of vk_hash ---------------------------------
        // This <2> is the depth of the vk tree
        let calc_vk_root_var =
            BinaryMerkleTreeGadget::<VK_PATHS_LEN, C1::BaseField>::calculate_root(
                &mut circuit,
                vk_var_hash,
                input.vk_path_index,
                input.vk_paths.clone().try_into().map_err(|_| {
                    CircuitError::ParameterError("Unexpected number of VK".to_string())
                })?,
            )?;
        circuit.enforce_equal(calc_vk_root_var, global_vk_root_var)?;

        let mut input_nullifier_hashes = vec![];
        let mut nullifiers_fq = vec![];
        let mut input_commitment_tree_root_vars = vec![];
        // These steps occur for every nullifier in each input
        for i in 0..N {
            //--------Step 3: Membership check of client commitment tree roots in global commitment root ------
            // This happens per nullifier as a user can use commitments from different blocks
            let (commitment_tree_root_var, nullifier) =
                client_commitment_membership_check::<C1, C2, D>(
                    &mut circuit,
                    input,
                    global_commitment_root_var,
                    i,
                )?;
            input_commitment_tree_root_vars.push(commitment_tree_root_var); // OUT
            nullifiers_fq.push(nullifier); // OUT
            let nullifier_is_zero = circuit.is_zero(nullifier)?;

            //--------Step 4: Check nullifier and low nullifier for correctness  ------
            // Check nullifier is "step over" of low_nullifier (Sandwich condition)
            // If the next_value &  next_index in low nullifier == 0, then check nullifier.value >
            // low_null.value (Max condition)
            // Extract low nullifier value, next value and next index
            let low_nullifer_next_value_var =
                circuit.create_variable(input.low_nullifier[i].next_value())?;
            let low_nullifier_next_index_var = circuit
                .create_variable(C1::BaseField::from(input.low_nullifier[i].next_index()))?;
            let low_nullifier_value_var =
                circuit.create_variable(input.low_nullifier[i].value())?;

            // Check if the next value and next index are zero
            let low_nullifier_next_value_is_zero = circuit.is_zero(low_nullifer_next_value_var)?;
            let low_nullifier_next_index_is_zero = circuit.is_zero(low_nullifier_next_index_var)?;
            let max_condition_next_are_zero = circuit.logic_and(
                low_nullifier_next_value_is_zero,
                low_nullifier_next_index_is_zero,
            )?;

            // Check if the nullifier is greater than the low nullifier value
            let low_nullifier_value_max = circuit.is_lt(low_nullifier_value_var, nullifier)?;
            // The max condition is if the nullifier is greater than the previous max (low nullifier)
            let max_condition =
                circuit.logic_and(max_condition_next_are_zero, low_nullifier_value_max)?;

            // In not MAX condition, we check the low nullifier is a "step over"
            // First condition, the low.next_value > nullifier
            let next_value_gt_nullifier = circuit.is_gt(low_nullifer_next_value_var, nullifier)?;
            // Second condition, the low.value < nullifier
            let low_nullifer_value_lt_nullifier =
                circuit.is_lt(nullifier, low_nullifier_value_var)?;
            // Therefore the nullifier is inbetween (sandwich)
            let sandwich_condition =
                circuit.logic_and(next_value_gt_nullifier, low_nullifer_value_lt_nullifier)?;

            // The low nullifier needs to be either a max condition or sandwich condition
            let condition_met = circuit.logic_or(max_condition, sandwich_condition)?;
            // Unless the nullifier is zero, then we trivially return true
            let condition_select = circuit.conditional_select(
                nullifier_is_zero,
                condition_met.into(),
                circuit.true_var().into(),
            )?;

            // This section only applies after the first nullifier is inserted //
            // Unless unless the low_nullifier is not in the existing tree
            // and is in the "pending subtree" (i.e. the previous nullifier)

            // If this is true, the low_nullifier is in the existing tree
            let low_nullifer_not_in_subtree =
                circuit.is_equal(condition_select, circuit.true_var().into())?;
            // Check if our nullifier is greater than the previously inserted nullifier
            let low_nullifier_is_prev_nullifier =
                circuit.is_gt(nullifier, prev_nullifier_low_nullifier[0])?;
            // The low nullifier is either the previous nullifier or in the existing tree
            let low_nullifier_condition =
                circuit.logic_or(low_nullifier_is_prev_nullifier, low_nullifer_not_in_subtree)?;
            circuit.enforce_true(low_nullifier_condition.into())?; // this is weird

            //--------Step 4.5: Check low nullifier set membership in global nullifier root ------
            let low_nullifier_hash = PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
                &mut circuit,
                [
                    low_nullifier_value_var,
                    low_nullifier_next_index_var,
                    low_nullifer_next_value_var,
                ]
                .as_slice(),
            )?;
            // This <32> is the depth of the Nullifier tree
            let calc_nullifier_root_var =
                BinaryMerkleTreeGadget::<32, C1::BaseField>::calculate_root(
                    &mut circuit,
                    low_nullifier_hash,
                    input.low_nullifier_indices[i],
                    input.low_nullifier_mem_path[i],
                )?;
            let nullifier_root_select = circuit.conditional_select(
                nullifier_is_zero,
                calc_nullifier_root_var,
                nullifier_new_root,
            )?;
            let nullifier_root_equality =
                circuit.is_equal(nullifier_new_root, nullifier_root_select)?;
            let nullifier_root_enforce_equal =
                circuit.logic_or(low_nullifier_is_prev_nullifier, nullifier_root_equality)?;
            circuit.enforce_true(nullifier_root_enforce_equal.into())?;

            // let new_low_nullifier_hash =
            //     PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
            //         &mut circuit,
            //         [low_nullifier_value_var, leaf_count, nullifier].as_slice(),
            //     )?;
            //
            let new_inserted_nullifier =
                PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
                    &mut circuit,
                    [
                        nullifier,
                        low_nullifier_next_index_var,
                        low_nullifer_next_value_var,
                    ]
                    .as_slice(),
                )?;
            let nullifier_to_be_pushed =
                circuit.conditional_select(nullifier_is_zero, new_inserted_nullifier, nullifier)?;
            input_nullifier_hashes.push(nullifier_to_be_pushed);
            // Step 8: Hash the input  nullifiers pairwise
            // Use low nullifier mem path but with new hash
            leaf_count = circuit.add_constant(leaf_count, &C1::BaseField::one())?;

            // nullifier_new_root = BinaryMerkleTreeGadget::<32, C1::BaseField>::calculate_root(
            //     &mut circuit,
            //     new_low_nullifier_hash,
            //     input.low_nullifier_indices[i],
            //     input.low_nullifier_mem_path[i],
            // )?;

            prev_nullifier_low_nullifier = [low_nullifier_value_var, leaf_count, nullifier];
            // ark_std::println!("Nullifier root: {:?}", circuit.witness(nullifier_new_root)?);
        }
        let swap_var = circuit.create_boolean_variable(input.swap_field)?;
        swap_vars.push(swap_var);
        // TODO: enforce I == 2 inside circuit
        if input.swap_field && (I != 2 || C != 2 || N != 1) {
            return Err(CircuitError::ParameterError(
                "Length of client inputs, commitments, or nullifiers is incorrect for swap"
                    .to_string(),
            ));
        }
        // In a swap, the first output commitment is c
        // Step 5: PV each input proof
        let proof_var = PlonkIpaSWProofNativeVar::create_variables(&mut circuit, &input.proof)?;
        let g_gen: SWPoint<C1::BaseField> = input.vk.open_key.g_bases[0].into();
        let commitments_fq = input
            .commitments
            .iter() // C
            .map(fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>)
            .collect::<Vec<_>>();
        let commitments_var = commitments_fq
            .into_iter()
            .map(|x| circuit.create_variable(x))
            .collect::<Result<Vec<_>, _>>()?;
        out_commitments.push(commitments_var.clone());
        let ciphertext_vars = input
            .ciphertext
            .iter()
            .map(|x| {
                let x = fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(x);
                circuit.create_variable(x)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let eph_pub_key_vars = input
            .eph_pub_key
            .iter()
            .map(|x| circuit.create_variable(*x))
            .collect::<Result<Vec<_>, _>>()?;
        // PI ordering is:
        // Swap field
        // Comm tree root(s)
        // Nullifier(s)
        // New Commitment(s)
        // Eph pub key (x2)
        // Ciphertext (x3)
        let mut public_input_var = vec![]; // = [0usize; 1 + 2*N + C + 5];
        public_input_var.push(swap_var.into());

        // Loops are good to make length obvious
        #[allow(clippy::needless_range_loop)]
        for i in 0..N {
            public_input_var.push(input_commitment_tree_root_vars[i]);
        }
        #[allow(clippy::needless_range_loop)]
        for i in 0..N {
            public_input_var.push(nullifiers_fq[i]);
        }
        #[allow(clippy::needless_range_loop)]
        for j in 0..C {
            public_input_var.push(commitments_var[j]);
        }
        #[allow(clippy::needless_range_loop)]
        for k in 0..EPHEMERAL_KEY_LEN {
            public_input_var.push(eph_pub_key_vars[k]);
        }
        #[allow(clippy::needless_range_loop)]
        for l in 0..CIPHERTEXT_LEN {
            public_input_var.push(ciphertext_vars[l]);
        }
        let (g_comm_var, u_challenge_var) = &verifying_key_var.partial_verify_circuit_ipa_native(
            &mut circuit,
            &g_gen,
            &public_input_var,
            &proof_var,
        )?;
        g_comms_vars.push(*g_comm_var);
        u_challenges_vars.push(*u_challenge_var);
        // ----- Reaching this points means we have a valid proof
        // ----- Now we need to increment state
        // Step 6: Prove correct Acc of PV outputs
        let g_comm = circuit.sw_point_witness(g_comm_var)?;
        let mut u_challenges = vec![];
        let u_challenge_fq = circuit.witness(*u_challenge_var)?;
        let u_challenge = field_switching::<C1::BaseField, C1::ScalarField>(&u_challenge_fq);
        u_challenges.push(u_challenge);

        let instance = PCSInstance::<UnivariateIpaPCS<C1>>::new(
            Commitment(g_comm.into()),
            C2::BaseField::from(0u64),
            u_challenge,
        );
        instances.push(instance);
        // Step 7: Hash the output commitments pairwise
        // This loop creates 2 subtrees of depth 1 (but really log2(C))
        //  This is only if transaction has > 1 commitment
        if C == 1 || input.swap_field {
            leaf_hashes.push(commitments_var[0]);
        } else {
            let subtree_leaf = poseidon_gadget::<C1, C2>(&mut circuit, &commitments_var, C)?;
            leaf_hashes.push(subtree_leaf);
        }

        if N == 1 {
            nullifier_leaf_hashes.push(input_nullifier_hashes[0]);
        } else {
            let nullifier_subtree_leaf =
                poseidon_gadget::<C1, C2>(&mut circuit, &input_nullifier_hashes, N)?;
            nullifier_leaf_hashes.push(nullifier_subtree_leaf);
        }

        if C == 1 {
            // fix out of bounds err
            // TODO make better if C = 1, since there is no swap
            out_commitments[input_idx].push(0);
        }
    }

    // Step 8: Swap Checks
    // TODO enforce I == 2 if swap in circuit
    let same_swap_fields = circuit.is_equal(swap_vars[0].into(), swap_vars[1].into())?;
    circuit.enforce_true(same_swap_fields.into())?;
    /*
       if C == 1 {
           // fix out of bounds err
           // TODO make better if C = 1, since there is no swap
           out_commitments[0].push(0);
           out_commitments[1].push(0);
       }
    */
    let out_1_match = circuit.is_equal(out_commitments[0][0], out_commitments[1][1])?;
    let out_2_match = circuit.is_equal(out_commitments[1][0], out_commitments[0][1])?;
    let both_match = circuit.logic_and(out_2_match, out_1_match)?;
    // Using swap[0] as we have already enforced equality across swap vars
    let check = circuit.conditional_select(swap_vars[0], 1, both_match.into())?;
    circuit.enforce_true(check)?;

    let prover = AccProver::new();
    // 1 SW Point + 2 Field element made public here
    let (acc, pi_star) = prover
        .prove_accumulation(&commit_key, &instances, &g_polys)
        .unwrap();

    circuit.set_variable_public(nullifier_new_root)?;
    // Bag the roots of the subtrees created previously assuming I == 2
    let commitment_subtree_root = poseidon_gadget::<C1, C2>(&mut circuit, &leaf_hashes, I)?;
    circuit.set_variable_public(commitment_subtree_root)?;
    let nullifier_subtree_root =
        poseidon_gadget::<C1, C2>(&mut circuit, &nullifier_leaf_hashes, I)?;
    circuit.set_variable_public(nullifier_subtree_root)?;

    // nullfier_leaf_hash [left_n, right_n]
    // IF left_n && right_n == 0, then nullifier_subtree_root = zero
    // ELSE if left_n == 0, then swap left_n and right_n => H(right_n, left_n)
    // otherwise H(left_n, right_n)
    // let left = nullifier_leaf_hashes[0];
    // let right = nullifier_leaf_hashes[1];
    // let left_is_zero = circuit.is_zero(left)?;
    // let right_is_zero = circuit.is_zero(right)?;
    // let right_is_not_zero = circuit.logic_neg(right_is_zero)?;
    // let left_and_right_zero = circuit.logic_and(left_is_zero, right_is_zero)?;
    //
    // let swap_condition = circuit.logic_and(left_is_zero, right_is_not_zero)?;
    // let left = circuit.conditional_select(swap_condition, left, right)?;
    // let right = circuit.conditional_select(swap_condition, right, left)?;
    //
    // // Bag the roots of the nullifier subtrees created previously assuming I == 2
    // let left_right_nullifier_hash = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
    //     &mut circuit,
    //     [left, right].as_slice(),
    // )?;
    // let nullifier_subtree_root = circuit.conditional_select(
    //     left_and_right_zero,
    //     left_right_nullifier_hash,
    //     circuit.zero(),
    // )?;
    verify_accumulation_gadget_sw_native::<
        C1,
        C2,
        _,
        _,
        <<C1 as Pairing>::G1 as CurveGroup>::Config,
    >(
        &mut circuit,
        &g_comms_vars[..],
        &vec![0; I],
        &u_challenges_vars[..],
        &acc,
    )?;
    circuit.check_circuit_satisfiability(&circuit.public_input()?)?;
    circuit.finalize_for_arithmetization()?;

    Ok((circuit, pi_star))
}
