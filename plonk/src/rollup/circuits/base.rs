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

mod helpers;
use helpers::*;

#[allow(clippy::type_complexity)]
pub fn base_rollup_circuit<C1, C2, const I: usize, const C: usize, const N: usize, const D: usize>(
    client_inputs: [ClientInput<C1, C, N, D>; I],
    global_vk_root: C2::ScalarField,
    global_nullifier_root: C2::ScalarField,
    global_nullifier_leaf_count: C2::ScalarField,
    global_commitment_root: C2::ScalarField,
    g_polys: [DensePolynomial<C2::BaseField>; I],
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
        create_initial_low_nullifier_vars(&mut circuit, &client_inputs[0])?;

    // These values are hardcoded based on turbo_plonk vks
    for input in client_inputs {
        //----------------------------Step 1: Hash Verification Key ---------------------------------
        let (verifying_key_var, vk_var_hash) =
            hash_verification_key::<C1, C2, C, N, D>(&mut circuit, &input.vk)?;

        //------------------------------------------------------------------------------

        //----------------------------Step 2: Membership check of vk_hash ---------------------------------
        // This <2> is the depth of the vk tree
        let calc_vk_root_var = BinaryMerkleTreeGadget::<2, C1::BaseField>::calculate_root(
            &mut circuit,
            vk_var_hash,
            input.vk_path_index,
            input.vk_paths,
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
                client_commitment_membership_check::<C1, C2, C, N, D>(
                    &mut circuit,
                    &input,
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
        } else if C < 5 {
            let subtree_leaf = poseidon_gadget::<C1, C2, C>(&mut circuit, &commitments_var)?;
            leaf_hashes.push(subtree_leaf);
        } else {
            unimplemented!()
        }

        if N == 1 {
            nullifier_leaf_hashes.push(input_nullifier_hashes[0]);
        } else if N < 5 {
            let nullifier_subtree_leaf =
                poseidon_gadget::<C1, C2, N>(&mut circuit, &input_nullifier_hashes)?;
            nullifier_leaf_hashes.push(nullifier_subtree_leaf);
        } else {
            unimplemented!()
        }
    }

    // Step 8: Swap Checks
    // TODO enforce I == 2 if swap in circuit
    let same_swap_fields = circuit.is_equal(swap_vars[0].into(), swap_vars[1].into())?;
    circuit.enforce_true(same_swap_fields.into())?;
    if C == 1 {
        // fix out of bounds err
        // TODO make better if C = 1, since there is no swap
        out_commitments[1].push(0);
        out_commitments[0].push(0);
    }
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
    if I < 9 {
        let commitment_subtree_root = poseidon_gadget::<C1, C2, I>(&mut circuit, &leaf_hashes)?;
        circuit.set_variable_public(commitment_subtree_root)?;
        let nullifier_subtree_root =
            poseidon_gadget::<C1, C2, I>(&mut circuit, &nullifier_leaf_hashes)?;
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
    } else {
        unimplemented!()
    }
    verify_accumulation_gadget_sw_native::<
        C1,
        C2,
        _,
        _,
        <<C1 as Pairing>::G1 as CurveGroup>::Config,
    >(
        &mut circuit,
        &g_comms_vars[..],
        &[0; I],
        &u_challenges_vars[..],
        &acc,
    )?;

    Ok((circuit, pi_star))
}

#[cfg(test)]
pub mod base_test {
    use crate::client::PlonkCircuitParams;
    use ark_ec::pairing::Pairing;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::CurveGroup;
    use ark_ff::Zero;
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;
    use common::crypto::poseidon::Poseidon;
    use curves::pallas::Affine as PAffine;
    use curves::pallas::{Fq, Fr, PallasConfig};
    use curves::vesta::VestaConfig;
    use jf_plonk::nightfall::ipa_structs::{ProvingKey, VerifyingKey};
    use jf_plonk::nightfall::PlonkIpaSnark;
    use jf_plonk::proof_system::UniversalSNARK;
    use jf_plonk::transcript::RescueTranscript;
    use jf_primitives::pcs::StructuredReferenceString;
    use jf_relation::gadgets::ecc::short_weierstrass::SWPoint;
    use jf_relation::PlonkCircuit;
    use jf_relation::{Arithmetization, Circuit};
    use jf_utils::{field_switching, fq_to_fr_with_mask, test_rng};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use std::str::FromStr;
    use trees::membership_tree::{MembershipTree, Tree};
    use trees::non_membership_tree::IndexedMerkleTree;
    use trees::non_membership_tree::NonMembershipTree;
    use trees::tree::AppendTree;
    use zk_macros::client_circuit;

    use crate::client::circuits::mint;
    use crate::client::circuits::swap::swap_circuit;
    use crate::client::circuits::transfer;

    use crate::rollup::circuits::base::BasePublicVarIndex;
    use crate::rollup::circuits::client_input::{ClientInputBuilder, LowNullifierInfo};
    use crate::rollup::circuits::structs::{AccInstance, GlobalPublicInputs, SubTrees};
    use crate::rollup::circuits::utils::StoredProof;
    use crate::utils::bench::tree::tree_generator;

    use super::{base_rollup_circuit, ClientInput};

    #[test]
    fn test_base_circuit() {
        test_base_rollup_helper_mint::<2, 2, 8>();
        // test_base_rollup_helper_mint::<2, 4>();
        // test_base_rollup_helper_mint::<4, 2>();
        test_base_rollup_helper_transfer::<2, 2, 2, 8>();
        // test_base_rollup_helper_transfer::<4, 2, 2,8>();
        // test_base_rollup_helper_transfer::<4, 4, 1,8>();

        test_base_rollup_helper_swap::<8>();
    }

    use crate::primitives::circuits::kem_dem::KemDemParams;
    use ark_ec::short_weierstrass::Affine;
    use ark_ec::short_weierstrass::Projective;
    use ark_ec::CurveConfig;
    use ark_ff::PrimeField;
    use common::crypto::poseidon::constants::PoseidonParams;
    use jf_plonk::nightfall::ipa_structs::Proof;
    use jf_primitives::rescue::RescueParameter;
    use jf_relation::gadgets::ecc::SWToTEConParam;

    #[client_circuit]
    fn generate_and_verify<P, V, VSW>(
        circuit: PlonkCircuit<V::ScalarField>,
    ) -> Result<
        (
            Proof<V>,
            DensePolynomial<V::ScalarField>,
            ProvingKey<V>,
            VerifyingKey<V>,
        ),
        String,
    > {
        let mut rng = ChaChaRng::from_entropy();
        let ipa_srs = <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(
            circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
        let (ipa_pk, ipa_vk) = PlonkIpaSnark::<V>::preprocess(&ipa_srs, &circuit).unwrap();

        let (ipa_proof, g_poly, _) = PlonkIpaSnark::<V>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<V as Pairing>::BaseField>,
        >(&mut rng, &circuit, &ipa_pk, None)
        .unwrap();
        PlonkIpaSnark::<V>::verify::<RescueTranscript<<V as Pairing>::BaseField>>(
            &ipa_vk,
            &circuit.public_input().unwrap(),
            &ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Client proof verified");

        Ok((ipa_proof, g_poly, ipa_pk, ipa_vk))
    }

    fn test_base_rollup_helper_mint<const I: usize, const C: usize, const D: usize>() {
        let mut rng = ChaChaRng::from_entropy();
        let mut client_inputs = vec![];
        let mut g_polys = vec![];
        let token_id = Some(Fq::rand(&mut rng));
        for _i in 0..I {
            let PlonkCircuitParams {
                circuit: mint_circuit,
                public_inputs: mint_inputs,
            } = mint::utils::mint_with_random_inputs::<PallasConfig, VestaConfig, _, C>(token_id)
                .unwrap();
            let (mint_ipa_proof, g_poly, _mint_ipa_pk, mint_ipa_vk) =
                generate_and_verify::<PallasConfig, VestaConfig, _>(mint_circuit).unwrap();
            ark_std::println!("Client proof verified");

            let input_builder = ClientInputBuilder::<VestaConfig, C, 1, D>::new();
            let mut client_input =
                ClientInput::<VestaConfig, C, 1, D>::new(mint_ipa_proof, mint_ipa_vk.clone());
            client_input.set_commitments(
                input_builder
                    .to_commitments_array(mint_inputs.commitments)
                    .unwrap(),
            );

            client_inputs.push(client_input);
            g_polys.push(g_poly);
        }

        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        // all have the same vk
        let vks = vec![client_inputs[0].vk.clone()];
        let comms: Vec<Fq> = vec![];
        let nullifiers: Vec<Fq> = vec![];
        let global_comm_roots: Vec<Fr> = vec![];
        let (vk_tree, _, nullifier_tree, global_comm_tree) =
            tree_generator(vks, comms, nullifiers, global_comm_roots);

        for ci in client_inputs.iter_mut() {
            ci.vk_paths = vk_tree.membership_witness(0).unwrap().try_into().unwrap();
            // vk index is already (correctly) zero
        }

        let vesta_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        ).unwrap();
        let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();
        let (mut base_rollup_circuit, _) =
            base_rollup_circuit::<VestaConfig, PallasConfig, I, C, 1, D>(
                client_inputs.try_into().unwrap(),
                vk_tree.root(),
                nullifier_tree.root(),
                nullifier_tree.leaf_count().into(),
                global_comm_tree.root(),
                g_polys.try_into().unwrap(),
                vesta_commit_key,
            )
            .unwrap();
        ark_std::println!(
            "Base rollup circuit constraints: {:?}",
            base_rollup_circuit.num_gates()
        );
        base_rollup_circuit
            .check_circuit_satisfiability(&base_rollup_circuit.public_input().unwrap())
            .unwrap();
        base_rollup_circuit.finalize_for_arithmetization().unwrap();
        let base_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_rollup_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (base_ipa_pk, base_ipa_vk) =
            PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_rollup_circuit).unwrap();
        let now = std::time::Instant::now();
        let base_ipa_proof = PlonkIpaSnark::<PallasConfig>::prove::<
            _,
            _,
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(&mut rng, &base_rollup_circuit, &base_ipa_pk, None)
        .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<PallasConfig>::verify::<
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(
            &base_ipa_vk,
            &base_rollup_circuit.public_input().unwrap(),
            &base_ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Base proof verified")
    }

    pub fn test_base_rollup_helper_transfer<
        const I: usize,
        const C: usize,
        const N: usize,
        const D: usize,
    >() -> StoredProof<PallasConfig, VestaConfig> {
        // Prepare transfer preamble (i.e. create fake mints)
        let mut rng = ChaChaRng::from_entropy();
        let mut client_inputs = vec![];
        let mut global_comm_roots: Vec<Fr> = vec![];
        let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
        let init_nullifier_root = nullifier_tree.root();
        let mut g_polys = vec![];

        let token_id = Some(Fq::rand(&mut rng));

        for _ in 0..I {
            let PlonkCircuitParams{ circuit:transfer_circuit, public_inputs: transfer_inputs} =
                transfer::utils::transfer_with_random_inputs::<PallasConfig, VestaConfig, _, C,N,D>(token_id).unwrap();
            let (transfer_ipa_proof, g_poly, _transfer_ipa_pk, transfer_ipa_vk) =
                generate_and_verify::<PallasConfig, VestaConfig, _>(transfer_circuit).unwrap();
            g_polys.push(g_poly);

            let input_builder = ClientInputBuilder::<VestaConfig, C, N, D>::new();
            let mut client_input = ClientInput::<VestaConfig, C, N, D>::new(
                transfer_ipa_proof,
                transfer_ipa_vk.clone(),
            );

            let switched_root: <VestaConfig as Pairing>::BaseField =
                field_switching(&transfer_inputs.commitment_root[0]);
            let nullifiers = input_builder
                .to_nullifiers_array(transfer_inputs.nullifiers)
                .unwrap();
            let LowNullifierInfo {
                nullifiers: low_nullifier,
                indices: low_nullifier_indices,
                paths: low_nullifier_mem_path,
            } = input_builder.update_nullifier_tree(&mut nullifier_tree, nullifiers);

            client_input
                .set_nullifiers(nullifiers)
                .set_commitments(
                    input_builder
                        .to_commitments_array(transfer_inputs.commitments)
                        .unwrap(),
                )
                .set_commitment_tree_root(
                    input_builder
                        .to_commitments_tree_root_array(transfer_inputs.commitment_root)
                        .unwrap(),
                )
                .set_low_nullifier_info(
                    low_nullifier,
                    low_nullifier_indices,
                    low_nullifier_mem_path,
                )
                .set_eph_pub_key(
                    input_builder
                        .to_eph_key_array(transfer_inputs.ephemeral_public_key)
                        .unwrap(),
                )
                .set_ciphertext(
                    input_builder
                        .to_ciphertext_array(transfer_inputs.ciphertexts)
                        .unwrap(),
                );

            client_inputs.push(client_input);
            global_comm_roots.push(switched_root);
        }

        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        // all have the same vk
        let vks = vec![client_inputs[0].vk.clone()];
        let comms: Vec<Fq> = vec![];

        let (vk_tree, _, _, global_comm_tree) =
            tree_generator(vks, comms, vec![], global_comm_roots);

        for (i, ci) in client_inputs.iter_mut().enumerate() {
            let global_root_path = global_comm_tree
                .membership_witness(i)
                .unwrap()
                .try_into()
                .unwrap();
            ci.path_comm_tree_root_to_global_tree_root = [global_root_path; N];
            ci.path_comm_tree_index = [Fr::from(i as u32); N];
            ci.vk_paths = vk_tree.membership_witness(0).unwrap().try_into().unwrap();
            // vk index is already (correctly) zero
        }

        let vesta_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        ).unwrap();
        let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

        let pallas_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        ).unwrap();
        let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();
        let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
        let (mut base_rollup_circuit, pi_star) =
            base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N, D>(
                client_inputs.try_into().unwrap(),
                vk_tree.root(),
                // initial_nullifier_tree.root,
                init_nullifier_root,
                (initial_nullifier_tree.leaf_count() as u64).into(),
                global_comm_tree.root(),
                g_polys.try_into().unwrap(),
                vesta_commit_key.clone(),
            )
            .unwrap();
        ark_std::println!(
            "Base rollup circuit constraints: {:?}",
            base_rollup_circuit.num_gates()
        );
        base_rollup_circuit
            .check_circuit_satisfiability(&base_rollup_circuit.public_input().unwrap())
            .unwrap();
        base_rollup_circuit.finalize_for_arithmetization().unwrap();
        let base_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_rollup_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (base_ipa_pk, base_ipa_vk) =
            PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_rollup_circuit).unwrap();
        let now = std::time::Instant::now();
        let (base_ipa_proof, g_poly, _) =
            PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<PallasConfig as Pairing>::BaseField>,
            >(&mut rng, &base_rollup_circuit, &base_ipa_pk, None)
            .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<PallasConfig>::verify::<
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(
            &base_ipa_vk,
            &base_rollup_circuit.public_input().unwrap(),
            &base_ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Running serial");
        // serial_to_file(
        //     base_ipa_proof.clone(),
        //     base_rollup_circuit.public_input().unwrap(),
        //     base_ipa_vk.clone(),
        //     (pallas_commit_key.clone(), vesta_commit_key.clone()),
        //     pi_star.clone(),
        //     "base_circuit_output.json",
        // );
        // ark_std::println!("Proof verified");

        //     (
        //         base_rollup_circuit,
        //         base_ipa_proof,
        //         base_ipa_vk,
        //         (vesta_commit_key, pallas_commit_key),
        //         pi_star,
        //     )
        let public_inputs = base_rollup_circuit.public_input().unwrap();
        let global_public_inputs = GlobalPublicInputs::from_vec(public_inputs.clone());
        let subtree_pi = SubTrees::from_vec(
            public_inputs[BasePublicVarIndex::CommitmentSubteeRoot as usize
                ..=BasePublicVarIndex::NullifierSubtreeRoot as usize]
                .to_vec(),
        );
        let instance: AccInstance<VestaConfig> = AccInstance {
            comm: SWPoint(
                public_inputs[BasePublicVarIndex::AccumulatorCommitmentX as usize],
                public_inputs[BasePublicVarIndex::AccumulatorCommitmentY as usize],
                public_inputs[BasePublicVarIndex::AccumulatorCommitmentX as usize] == Fr::zero(),
            ),
            // values are originally Vesta scalar => safe switch back into 'native'
            eval: field_switching(
                &public_inputs[BasePublicVarIndex::AccumulatorInstanceValue as usize],
            ),
            eval_point: field_switching(
                &public_inputs[BasePublicVarIndex::AccumulatorInstancePoint as usize],
            ),
        };

        StoredProof {
            proof: base_ipa_proof,
            pub_inputs: (global_public_inputs, subtree_pi, instance, vec![]),
            vk: base_ipa_vk,
            commit_key: (pallas_commit_key, vesta_commit_key),
            g_poly,
            pi_stars: (Default::default(), pi_star),
        }
    }

    fn test_base_rollup_helper_swap<const D: usize>() {
        const I: usize = 2;
        let mut rng = test_rng();
        let private_key_domain = Fq::from_str("1").unwrap();
        let nullifier_key_domain = Fq::from_str("2").unwrap();

        let mut client_inputs = vec![];
        let mut g_polys = vec![];
        let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
        let mut init_nullifier_root = Fr::zero();

        let mut values = vec![];
        let mut token_ids = vec![];
        let mut old_commitments = vec![];
        let mut old_nonces = vec![];
        let mut root_keys = vec![];
        let mut public_keys = vec![];

        // for each swap participant, prepare old commitment details
        for i in 0..I {
            let root_key = Fq::rand(&mut rng);
            let value = Fq::from((i + 1) as u64);
            let token_id = Fq::from((i + 10) as u64);
            let nonce = Fq::from((i + 100) as u64);

            let private_key: Fq = Poseidon::<Fq>::new()
                .hash(vec![root_key, private_key_domain])
                .unwrap();
            let private_key_trunc: Fr = fq_to_fr_with_mask(&private_key);

            let token_owner = (PallasConfig::GENERATOR * private_key_trunc).into_affine();

            let old_commitment_hash = Poseidon::<Fq>::new()
                .hash(vec![value, token_id, nonce, token_owner.x, token_owner.y])
                .unwrap();
            values.push(value);
            token_ids.push(token_id);
            old_commitments.push(old_commitment_hash);
            old_nonces.push(nonce);
            root_keys.push(root_key);
            public_keys.push(token_owner);
        }
        let comm_tree: Tree<Fq, D> = Tree::from_leaves(old_commitments);
        for i in 0..I {
            // other half of swap index
            let j = (i + 1) % 2;
            let old_sib_path = comm_tree.membership_witness(i).unwrap().try_into().unwrap();
            let (mut swap_circuit, (nullifier, commitments, eph_pub_key, ciphertext)) =
                swap_circuit_helper_generator(
                    values[i],
                    token_ids[i],
                    values[j],
                    token_ids[j],
                    old_sib_path,
                    old_nonces[i],
                    comm_tree.root(),
                    i as u64,
                    j as u64,
                    root_keys[i],
                    private_key_domain,
                    nullifier_key_domain,
                    public_keys[j],
                );
            swap_circuit.finalize_for_arithmetization().unwrap();
            let swap_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                swap_circuit.srs_size().unwrap(),
                &mut rng,
            ).unwrap();
            let (swap_ipa_pk, swap_ipa_vk) =
                PlonkIpaSnark::<VestaConfig>::preprocess(&swap_ipa_srs, &swap_circuit).unwrap();

            let (swap_ipa_proof, g_poly, _) =
                PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                    _,
                    _,
                    RescueTranscript<<VestaConfig as Pairing>::BaseField>,
                >(&mut rng, &swap_circuit, &swap_ipa_pk, None)
                .unwrap();
            PlonkIpaSnark::<VestaConfig>::verify::<
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(
                &swap_ipa_vk,
                &swap_circuit.public_input().unwrap(),
                &swap_ipa_proof,
                None,
            )
            .unwrap();
            ark_std::println!("Client proof verified");
            let lifted_nullifier = field_switching(&nullifier);
            let low_null = nullifier_tree.find_predecessor(lifted_nullifier);
            let low_path: [Fr; 32] = nullifier_tree
                .non_membership_witness(lifted_nullifier)
                .unwrap()
                .try_into()
                .unwrap();
            let low_index = Fr::from(low_null.tree_index as u32);
            // TODO what was this before? Can't we get the root from the tree initially?
            if i == 0 {
                let this_poseidon = Poseidon::<Fr>::new();
                let low_nullifier_hash = this_poseidon.hash_unchecked(vec![
                    low_null.node.value(),
                    Fr::from(low_null.tree_index as u64),
                    low_null.node.next_value(),
                ]);

                init_nullifier_root =
                    low_path
                        .into_iter()
                        .enumerate()
                        .fold(low_nullifier_hash, |acc, (i, curr)| {
                            if low_null.tree_index >> i & 1 == 0 {
                                this_poseidon.hash_unchecked(vec![acc, curr])
                            } else {
                                this_poseidon.hash(vec![curr, acc]).unwrap()
                            }
                        });
            }
            // nullifier_tree.append_leaf(null);
            nullifier_tree.update_low_nullifier(lifted_nullifier);

            let client_input: ClientInput<VestaConfig, 2, 1, D> = ClientInput {
                proof: swap_ipa_proof,
                swap_field: true,
                nullifiers: [nullifier],
                commitments,
                commitment_tree_root: [comm_tree.root()],
                path_comm_tree_root_to_global_tree_root: [[Fr::zero(); D]; 1], // filled later
                path_comm_tree_index: [Fr::zero()],                            // filled later
                low_nullifier: [low_null.node],
                low_nullifier_indices: [low_index],
                low_nullifier_mem_path: [low_path],
                vk_paths: [Fr::zero(), Fr::zero()], // filled later
                vk_path_index: Fr::from(0u64),
                vk: swap_ipa_vk.clone(),
                eph_pub_key: [
                    field_switching(&eph_pub_key[0]),
                    field_switching(&eph_pub_key[1]),
                ],
                ciphertext,
            };

            client_inputs.push(client_input);
            g_polys.push(g_poly);
        }

        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        // all have the same vk
        let vks = vec![client_inputs[0].vk.clone()];

        let (vk_tree, _, _, global_comm_tree) = tree_generator(
            vks,
            vec![],
            vec![],
            [field_switching(&comm_tree.root())].to_vec(),
        );

        for (_, ci) in client_inputs.iter_mut().enumerate() {
            // both use the same comm root
            let global_root_path = global_comm_tree
                .membership_witness(0)
                .unwrap()
                .try_into()
                .unwrap();
            ci.path_comm_tree_root_to_global_tree_root = [global_root_path];
            ci.path_comm_tree_index = [Fr::from(0 as u32)];
            ci.vk_paths = vk_tree.membership_witness(0).unwrap().try_into().unwrap();
            // vk index is already (correctly) zero
        }

        let vesta_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        ).unwrap();
        let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

        // let pallas_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
        //     2usize.pow(21),
        //     &mut rng,
        // ).unwrap();
        // let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();
        let (mut base_rollup_circuit, _pi_star) =
            base_rollup_circuit::<VestaConfig, PallasConfig, I, 2, 1, D>(
                client_inputs.try_into().unwrap(),
                vk_tree.root(),
                // initial_nullifier_tree.root,
                init_nullifier_root,
                Fr::from(0 as u32),
                global_comm_tree.root(),
                g_polys.try_into().unwrap(),
                vesta_commit_key.clone(),
            )
            .unwrap();
        ark_std::println!(
            "Base rollup circuit constraints: {:?}",
            base_rollup_circuit.num_gates()
        );
        base_rollup_circuit
            .check_circuit_satisfiability(&base_rollup_circuit.public_input().unwrap())
            .unwrap();
        base_rollup_circuit.finalize_for_arithmetization().unwrap();
        let base_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_rollup_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (base_ipa_pk, base_ipa_vk) =
            PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_rollup_circuit).unwrap();
        let now = std::time::Instant::now();
        let base_ipa_proof = PlonkIpaSnark::<PallasConfig>::prove::<
            _,
            _,
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(&mut rng, &base_rollup_circuit, &base_ipa_pk, None)
        .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<PallasConfig>::verify::<
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(
            &base_ipa_vk,
            &base_rollup_circuit.public_input().unwrap(),
            &base_ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Base proof verified");

        // uncomment below if we want to return and further roll this base

        // let public_inputs = base_rollup_circuit.public_input().unwrap();
        // let global_public_inputs = GlobalPublicInputs::from_vec(public_inputs.clone());
        // let subtree_pi = SubTrees::from_vec(public_inputs[5..=6].to_vec());
        // let instance: AccInstance<VestaConfig> = AccInstance {
        //     comm: SWPoint(
        //         public_inputs[7],
        //         public_inputs[8],
        //         public_inputs[9] == Fr::one(),
        //     ),
        //     // values are originally Vesta scalar => safe switch back into 'native'
        //     eval: field_switching(&public_inputs[10]),
        //     eval_point: field_switching(&public_inputs[11]),
        // };
        // StoredProof {
        //     proof: base_ipa_proof,
        //     pub_inputs: (global_public_inputs, subtree_pi, instance, vec![]),
        //     vk: base_ipa_vk,
        //     commit_key: (pallas_commit_key, vesta_commit_key),
        //     g_poly,
        //     pi_stars: (Default::default(), pi_star),
        // }
    }

    fn swap_circuit_helper_generator(
        old_value: Fq,
        old_token_id: Fq,
        new_value: Fq,
        new_token_id: Fq,
        old_sib_path: [Fq; 8],
        old_nonce: Fq,
        root: Fq,
        old_leaf_index: u64,
        new_leaf_index: u64, // = expected incoming commitment nonce
        root_key: Fq,        // required here as we need to keep keys consistent
        private_key_domain: Fq,
        nullifier_key_domain: Fq,
        recipient_public_key: PAffine,
    ) -> (PlonkCircuit<Fq>, (Fq, [Fq; 2], [Fq; 2], [Fq; 3])) {
        let ephemeral_key = Fq::rand(&mut test_rng());
        let circuit = swap_circuit::<PallasConfig, VestaConfig, 8>(
            old_value,
            old_nonce,
            old_sib_path.try_into().unwrap(),
            old_leaf_index.try_into().unwrap(),
            root,
            old_token_id,
            new_value,
            new_leaf_index.try_into().unwrap(),
            new_token_id,
            recipient_public_key,
            root_key,
            ephemeral_key,
            private_key_domain,
            nullifier_key_domain,
        )
        .unwrap();

        let public_inputs = circuit.public_input().unwrap();
        let len = public_inputs.len();
        assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());

        let client_input = (
            public_inputs[2].try_into().unwrap(),     // nullifiers
            public_inputs[3..=4].try_into().unwrap(), // new commitments
            public_inputs[len - 5..len - 3].try_into().unwrap(), // eph pub key
            public_inputs[len - 3..len].try_into().unwrap(), // ciphertext
        );
        (circuit, client_input)
    }
}
