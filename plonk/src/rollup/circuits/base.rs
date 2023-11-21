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
    circuit::plonk_partial_verifier::{PlonkIpaSWProofNativeVar, SWVerifyingKeyVar},
    ipa_structs::{CommitKey, Proof, VerifyingKey},
    UnivariateIpaPCS,
};
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::ecc::{short_weierstrass::SWPoint, SWToTEConParam},
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::{field_switching, fr_to_fq};
use trees::non_membership_tree::IndexedNode;

use crate::primitives::circuits::{
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};

// Fixed constants - I: Number of Input proofs (assume 2)
// C: number of commitments (1) , N: number of nullifiers(1)
pub struct ClientInput<E, const C: usize, const N: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    proof: Proof<E>,
    nullifiers: [E::ScalarField; N], // List of nullifiers in transaction
    commitments: [E::ScalarField; C], // List of commitments in transaction
    commitment_tree_root: [E::ScalarField; N], // Tree root for comm membership
    path_comm_tree_root_to_global_tree_root: [[E::BaseField; 8]; N],
    path_comm_tree_index: [E::BaseField; N],
    low_nullifier: [IndexedNode<E::BaseField>; N],
    low_nullifier_indices: [E::BaseField; N],
    low_nullifier_mem_path: [[E::BaseField; 32]; N], // Path for nullifier non membership
    vk_paths: [E::BaseField; 1],
    vk_path_index: E::BaseField,
    vk: VerifyingKey<E>,
    ciphertext: [E::ScalarField; 3],
}

pub fn base_rollup_circuit<C1, C2, const I: usize, const C: usize, const N: usize>(
    client_inputs: [ClientInput<C1, C, N>; I],
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
    let mut nullifier_new_root = circuit.create_public_variable(global_nullifier_root)?;
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

    let initial_low_nullifier_value =
        circuit.create_variable(field_switching(&client_inputs[0].nullifiers[0]))?;
    let initial_low_nullifier_next_index =
        circuit.create_variable((client_inputs[0].low_nullifier[0].next_index as u64).into())?;
    let initial_low_nullifier_next_value =
        circuit.create_variable(field_switching(&client_inputs[0].nullifiers[0]))?;
    let mut prev_nullifier_low_nullifier = [
        initial_low_nullifier_value,
        initial_low_nullifier_next_index,
        initial_low_nullifier_next_value,
    ];
    // These values are hardcoded based on turbo_plonk vks
    for input in client_inputs {
        //----------------------------Step 1: Hash Verification Key ---------------------------------
        let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &input.vk)?;
        // This vec, first 10 elements are sigma_comms
        let verifying_key_var_vec = verifying_key_var.to_vec();
        let sigma_comms = verifying_key_var_vec[0..10].to_vec();
        let sigma_comms_pairs = sigma_comms
            .iter()
            .step_by(2)
            .zip(sigma_comms.iter().skip(1).step_by(2));
        let mut sigma_hashes_leaves = sigma_comms_pairs
            .map(|(&x, &y)| {
                PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
                    &mut circuit,
                    [x, y].as_slice(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The selector comms are the remaining elements
        let selector_comms = verifying_key_var_vec[10..].to_vec();
        let selector_comms_pairs = selector_comms
            .iter()
            .step_by(2)
            .zip(selector_comms.iter().skip(1).step_by(2));
        let selector_hashes_leaves = selector_comms_pairs
            .map(|(&x, &y)| {
                PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
                    &mut circuit,
                    [x, y].as_slice(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        sigma_hashes_leaves.extend(selector_hashes_leaves);
        // We take the first two so we have even hashes up the tree (18 original elements)
        let mut total_leaves = sigma_hashes_leaves[2..].to_vec();
        let outlier_pair: (Variable, Variable) = (sigma_hashes_leaves[0], sigma_hashes_leaves[1]);
        // This is 4 because we have 4 levels of hashing (16 elements)
        for _ in 0..4 {
            let lefts = total_leaves.iter().step_by(2);
            let rights = total_leaves.iter().skip(1).step_by(2);
            let pairs = lefts.zip(rights);
            total_leaves = pairs
                .map(|(&x, &y)| {
                    PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
                        &mut circuit,
                        [x, y].as_slice(),
                    )
                })
                .collect::<Result<Vec<_>, _>>()?;
        }
        // The is the final hash of the outliers and the root of the mini tree
        let vk_var_hash = PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
            &mut circuit,
            [outlier_pair.0, outlier_pair.1, total_leaves[0]].as_slice(),
        )?;

        //------------------------------------------------------------------------------

        //----------------------------Step 2: Membership check of vk_hash ---------------------------------
        // This <1> is the depth of the vk tree
        let calc_vk_root_var = BinaryMerkleTreeGadget::<1, C1::BaseField>::calculate_root(
            &mut circuit,
            vk_var_hash,
            input.vk_path_index,
            input.vk_paths,
        )?;
        circuit.enforce_equal(calc_vk_root_var, global_vk_root_var)?;

        let mut input_nullifier_hashes = vec![];
        // These steps occur for every nullifier in each input
        for i in 0..N {
            //--------Step 3: Membership check of client commitment tree roots in global commitment root ------
            // This happens per nullifier as a user can use commitments from different blocks
            let commitment_tree_root_fq = fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(
                &input.commitment_tree_root[i],
            );
            let commitment_tree_root_var = circuit.create_variable(commitment_tree_root_fq)?;
            let calc_commitment_root_var =
                // This <8> is the depth of the block level commitment tree
                BinaryMerkleTreeGadget::<8, C1::BaseField>::calculate_root(
                    &mut circuit,
                    commitment_tree_root_var,
                    input.path_comm_tree_index[i],
                    input.path_comm_tree_root_to_global_tree_root[i],
                )?;

            // Nullifiers are in Vesta Fr and are safely lifted to this Pallas Fr (which is Vesta Fq)
            let nullifier_fq =
                fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(&input.nullifiers[i]);
            let nullifier = circuit.create_variable(nullifier_fq)?;
            // Conditional check if nullifier is zero
            let nullifier_is_zero = circuit.is_zero(nullifier)?;
            // If the nullifier is zero, then we need to trivially pass the root check
            let calc_commitment_root_select = circuit.conditional_select(
                nullifier_is_zero,
                calc_commitment_root_var,
                global_commitment_root_var,
            )?;
            circuit.enforce_equal(calc_commitment_root_select, global_commitment_root_var)?;

            //--------Step 4: Check nullifier and low nullifier for correctness  ------
            // Check nullifier is "step over" of low_nullifier (Sandwich condition)
            // If the next_value &  next_index in low nullifier == 0, then check nullifier.value >
            // low_null.value (Max condition)
            // Extract low nullifier value, next value and next index
            let low_nullifer_next_value_var =
                circuit.create_variable(input.low_nullifier[i].next_value)?;
            let low_nullifier_next_index_var = circuit.create_variable(C1::BaseField::from(
                input.low_nullifier[i].next_index as u64,
            ))?;
            let low_nullifier_value_var = circuit.create_variable(input.low_nullifier[i].value)?;

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

            let new_low_nullifier_hash =
                PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
                    &mut circuit,
                    [low_nullifier_value_var, leaf_count, nullifier].as_slice(),
                )?;

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
            nullifier_new_root = BinaryMerkleTreeGadget::<32, C1::BaseField>::calculate_root(
                &mut circuit,
                new_low_nullifier_hash,
                input.low_nullifier_indices[i],
                input.low_nullifier_mem_path[i],
            )?;
            prev_nullifier_low_nullifier = [low_nullifier_value_var, leaf_count, nullifier];
            ark_std::println!("Nullifier root: {:?}", circuit.witness(nullifier_new_root)?);
        }
        // Step 5: PV each input proof
        let proof_var = PlonkIpaSWProofNativeVar::create_variables(&mut circuit, &input.proof)?;
        let g_gen: SWPoint<C1::BaseField> = input.vk.open_key.g_bases[0].into();
        let nullifier_fq = input
            .nullifiers
            .iter() // N
            .map(|x| {
                let x = fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(x);
                circuit.create_variable(x)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let commitments_fq = input
            .commitments
            .iter() // C
            .map(fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>)
            .collect::<Vec<_>>();
        let commitments_var = commitments_fq
            .into_iter()
            .map(|x| circuit.create_variable(x))
            .collect::<Result<Vec<_>, _>>()?;
        let ciphertext_vars = input
            .ciphertext
            .iter()
            .map(|x| {
                let x = fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(x);
                circuit.create_variable(x)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let public_input_var = [
            nullifier_fq[0],
            commitments_var[0],
            ciphertext_vars[0],
            ciphertext_vars[1],
            ciphertext_vars[2],
        ]; // Come back to this
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
        let g_comms = vec![circuit.sw_point_witness(g_comm_var)?];
        let mut u_challenges = vec![];
        let u_challenge_fq = circuit.witness(*u_challenge_var)?;
        let u_challenge = field_switching::<C1::BaseField, C1::ScalarField>(&u_challenge_fq);
        u_challenges.push(u_challenge);

        for i in 0..g_comms.len() {
            let instance = PCSInstance::<UnivariateIpaPCS<C1>>::new(
                Commitment(g_comms[i].into()),
                C2::BaseField::from(0u64),
                u_challenges[i],
            );
            instances.push(instance);
        }
        // Step 7: Hash the output commitments pairwise
        // This loop creates 2 subtrees of depth 1 (but really log2(C))
        //  This is only if transaction has > 1 commitment
        // let subtree_leaf = PoseidonGadget::<PoseidonStateVar<2>, C1::BaseField>::hash(
        //     &mut circuit,
        //     commitments_var.as_slice(),
        // )?;
        // leaf_hashes.push(subtree_leaf);
        leaf_hashes.push(commitments_var[0]);

        //  This is only if transaction has > 1 nullifier
        // let nullifier_subtree_leaf = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
        //     &mut circuit,
        //     input_nullifier_hashes.as_slice(),
        // )?;
        // nullifier_leaf_hashes.push(nullifier_subtree_leaf);
        nullifier_leaf_hashes.push(input_nullifier_hashes[0]);
    }

    let prover = AccProver::new();
    // 1 SW Point + 2 Field element made public here
    let (acc, pi_star) = prover
        .prove_accumulation(&commit_key, &instances, &g_polys)
        .unwrap();

    circuit.set_variable_public(nullifier_new_root)?;
    // Bag the roots of the subtrees created previously assuming I == 2
    let commitment_subtree_root = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
        &mut circuit,
        leaf_hashes.as_slice(),
    )?;
    circuit.set_variable_public(commitment_subtree_root)?;

    // nullfier_leaf_hash [left_n, right_n]
    // IF left_n && right_n == 0, then nullifier_subtree_root = zero
    // ELSE if left_n == 0, then swap left_n and right_n => H(right_n, left_n)
    // otherwise H(left_n, right_n)
    let left = nullifier_leaf_hashes[0];
    let right = nullifier_leaf_hashes[1];
    let left_is_zero = circuit.is_zero(left)?;
    let right_is_zero = circuit.is_zero(right)?;
    let right_is_not_zero = circuit.logic_neg(right_is_zero)?;
    let left_and_right_zero = circuit.logic_and(left_is_zero, right_is_zero)?;

    let swap_condition = circuit.logic_and(left_is_zero, right_is_not_zero)?;
    let left = circuit.conditional_select(swap_condition, left, right)?;
    let right = circuit.conditional_select(swap_condition, right, left)?;

    // Bag the roots of the nullifier subtrees created previously assuming I == 2
    let left_right_nullifier_hash = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
        &mut circuit,
        [left, right].as_slice(),
    )?;
    let nullifier_subtree_root = circuit.conditional_select(
        left_and_right_zero,
        left_right_nullifier_hash,
        circuit.zero(),
    )?;
    circuit.set_variable_public(nullifier_subtree_root)?;
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
    use ark_ec::pairing::Pairing;
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::CurveGroup;
    use ark_ff::{One, Zero};
    use ark_poly::univariate::DensePolynomial;
    use ark_std::UniformRand;
    use common::crypto::poseidon::Poseidon;
    use curves::pallas::{Affine, Fq, Fr, PallasConfig};
    use curves::vesta::VestaConfig;
    use jf_plonk::nightfall::ipa_structs::{CommitKey, Proof, VerifyingKey};
    use jf_plonk::nightfall::PlonkIpaSnark;
    use jf_plonk::proof_system::structs::VK;
    use jf_plonk::proof_system::UniversalSNARK;
    use jf_plonk::transcript::RescueTranscript;
    use jf_primitives::pcs::StructuredReferenceString;
    use jf_relation::gadgets::ecc::short_weierstrass::SWPoint;
    use jf_relation::PlonkCircuit;
    use jf_relation::{Arithmetization, Circuit};
    use jf_utils::{field_switching, test_rng};
    use std::str::FromStr;
    use trees::membership_tree::{MembershipTree, Tree};
    use trees::non_membership_tree::IndexedMerkleTree;
    use trees::non_membership_tree::NonMembershipTree;
    use trees::tree::AppendTree;

    use crate::client::circuits::mint::mint_circuit;
    use crate::client::circuits::transfer::transfer_circuit;
    use crate::rollup::circuits::structs::{AccInstance, GlobalPublicInputs, SubTrees};
    use crate::rollup::circuits::utils::{serial_to_file, StoredProof};

    use super::{base_rollup_circuit, ClientInput};
    #[test]
    fn test_base_circuit() {
        // test_base_rollup_helper_mint();
        test_base_rollup_helper_transfer();
    }

    fn test_base_rollup_helper_mint() {
        let mut mint_circuit = mint_circuit_helper_generator(Fq::one());
        let mut mint_circuit_2 = mint_circuit_helper_generator(Fq::one() + Fq::one());
        let mut rng = test_rng();
        mint_circuit.finalize_for_arithmetization().unwrap();
        mint_circuit_2.finalize_for_arithmetization().unwrap();
        let mint_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            mint_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();

        let (mint_ipa_pk, mint_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&mint_ipa_srs, &mint_circuit).unwrap();
        let (mint_ipa_pk_2, _) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&mint_ipa_srs, &mint_circuit_2).unwrap();
        // ark_std::println!("Mint circuit vk: {:?}", mint_ipa_vk_2);
        let (mint_ipa_proof, g_poly, _) = PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(&mut rng, &mint_circuit, &mint_ipa_pk, None)
        .unwrap();
        let (mint_ipa_proof_2, g_poly_2, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &mint_circuit_2, &mint_ipa_pk_2, None)
            .unwrap();
        PlonkIpaSnark::<VestaConfig>::verify::<
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(
            &mint_ipa_vk,
            &mint_circuit_2.public_input().unwrap(),
            &mint_ipa_proof_2,
            None,
        )
        .unwrap();
        ark_std::println!("Proof verified");
        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        let vks = vec![mint_ipa_vk.clone()];
        let comms: Vec<Fq> = vec![];
        let nullifiers: Vec<Fq> = vec![];
        let global_comm_roots: Vec<Fr> = vec![];
        let (vk_tree, commitment_tree, nullifier_tree, global_comm_tree) =
            tree_generator(vks, comms, nullifiers, global_comm_roots);
        // Mint is the first slot
        let vk_paths = [
            vk_tree.membership_witness(0).unwrap(),
            vk_tree.membership_witness(0).unwrap(),
        ];
        let client_input: ClientInput<VestaConfig, 1, 1> = ClientInput {
            proof: mint_ipa_proof,
            nullifiers: [Fq::zero()],
            commitments: [mint_circuit.public_input().unwrap()[1]]
                .as_slice()
                .try_into()
                .unwrap(),
            commitment_tree_root: [commitment_tree.root.0],
            path_comm_tree_root_to_global_tree_root: [[Fr::zero(); 8]; 1],
            path_comm_tree_index: [Fr::zero()],
            low_nullifier: [Default::default()],
            low_nullifier_indices: [Fr::one()],
            low_nullifier_mem_path: [[Fr::zero(); 32]],
            vk_paths: vk_paths[0].clone().try_into().unwrap(),
            vk_path_index: Fr::from(0u64),
            vk: mint_ipa_vk.clone(),
            ciphertext: [Fq::zero(); 3],
        };
        // Print client input 1 public inputs
        let client_input_2: ClientInput<VestaConfig, 1, 1> = ClientInput {
            proof: mint_ipa_proof_2,
            nullifiers: [Fq::zero()],
            commitments: [mint_circuit_2.public_input().unwrap()[1]]
                .as_slice()
                .try_into()
                .unwrap(),
            commitment_tree_root: [commitment_tree.root.0],
            path_comm_tree_root_to_global_tree_root: [[Fr::zero(); 8]; 1],
            path_comm_tree_index: [Fr::zero()],
            low_nullifier: [Default::default()],
            low_nullifier_indices: [Fr::one()],
            low_nullifier_mem_path: [[Fr::zero(); 32]],
            vk_paths: vk_paths[0].clone().try_into().unwrap(),
            vk_path_index: Fr::from(0u64),
            vk: mint_ipa_vk,
            ciphertext: [Fq::zero(); 3],
        };

        let (commit_key_vesta, _) = mint_ipa_srs.trim(mint_circuit.srs_size().unwrap()).unwrap();
        let (mut base_rollup_circuit, _) =
            base_rollup_circuit::<VestaConfig, PallasConfig, 2, 1, 1>(
                [client_input, client_input_2],
                vk_tree.root.0,
                nullifier_tree.root,
                nullifier_tree.leaf_count.into(),
                global_comm_tree.root.0,
                [g_poly, g_poly_2],
                commit_key_vesta,
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
        ark_std::println!("Proof verified")
    }

    pub fn test_base_rollup_helper_transfer() -> StoredProof<PallasConfig, VestaConfig>
//     PlonkCircuit<Fr>,
    //     Proof<PallasConfig>,
    //     VerifyingKey<PallasConfig>,
    //     (CommitKey<VestaConfig>, CommitKey<PallasConfig>),
    //     DensePolynomial<Fq>,
    {
        // Prepare transfer preamble (i.e. create fake mints)
        let poseidon = Poseidon::<Fq>::new();
        let root_key = Fq::rand(&mut test_rng());
        let private_key_domain = Fq::from_str("1").unwrap();
        let private_key: Fq = Poseidon::<Fq>::new()
            .hash(vec![root_key, private_key_domain])
            .unwrap();
        let private_key_fr: Fr = field_switching(&private_key);

        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from(3u32);
        let token_owner = (PallasConfig::GENERATOR * private_key_fr).into_affine();

        let mint_commitments = [Fq::one(), Fq::one() + Fq::one()]
            .into_iter()
            .map(|v| {
                poseidon.hash_unchecked(vec![
                    v,
                    token_id,
                    token_nonce,
                    token_owner.x,
                    token_owner.y,
                ])
            })
            .collect::<Vec<_>>();
        let prev_commitment_tree = Tree::<Fq, 8>::from_leaves(mint_commitments.clone());
        // Build transfer circuits
        let mut transfer_circuits = mint_commitments
            .iter()
            .enumerate()
            .map(|(i, &_)| {
                let old_sib_path = prev_commitment_tree.membership_witness(i).unwrap();

                transfer_circuit_helper_generator(
                    Fq::from((i + 1) as u64),
                    old_sib_path,
                    prev_commitment_tree.root.0,
                    i as u64,
                )
            })
            .collect::<Vec<_>>();

        let mut rng = test_rng();
        transfer_circuits
            .iter_mut()
            .for_each(|c| c.finalize_for_arithmetization().unwrap());
        let transfer_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            transfer_circuits[0].srs_size().unwrap(),
            &mut rng,
        ).unwrap();

        let (transfer_ipa_pk, transfer_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&transfer_ipa_srs, &transfer_circuits[0])
                .unwrap();
        let (transfer_ipa_pk_2, _) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&transfer_ipa_srs, &transfer_circuits[1])
                .unwrap();
        // ark_std::println!("Mint circuit vk: {:?}", mint_ipa_vk_2);
        let (transfer_ipa_proof, g_poly, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &transfer_circuits[0], &transfer_ipa_pk, None)
            .unwrap();
        let (transfer_ipa_proof_2, g_poly_2, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &transfer_circuits[1], &transfer_ipa_pk_2, None)
            .unwrap();
        PlonkIpaSnark::<VestaConfig>::verify::<
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(
            &transfer_ipa_vk,
            &transfer_circuits[1].public_input().unwrap(),
            &transfer_ipa_proof_2,
            None,
        )
        .unwrap();
        ark_std::println!("Proof verified");

        /* ----------------------------------------------------------------------------------
         * ---------------------------  Base Rollup Circuit ----------------------------------
         * ----------------------------------------------------------------------------------
         */

        let vks = vec![transfer_ipa_vk.clone()];
        let comms: Vec<Fq> = vec![];
        let nullifiers: Vec<Fq> = transfer_circuits
            .iter()
            .map(|t| t.public_input().unwrap()[0])
            .collect::<Vec<_>>();
        let lifted_nullifiers = nullifiers
            .iter()
            .map(field_switching::<Fq, Fr>)
            .collect::<Vec<_>>();

        let global_comm_roots: Vec<Fr> = vec![field_switching(&prev_commitment_tree.root.0)];
        let (vk_tree, _, _, global_comm_tree) =
            tree_generator(vks, comms, vec![], global_comm_roots);
        let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
        let low_nullifier = nullifier_tree.find_predecessor(lifted_nullifiers[0]);

        // Mint is the first slot
        let vk_paths = [
            vk_tree.membership_witness(0).unwrap(),
            vk_tree.membership_witness(0).unwrap(),
        ];
        let poseidon = Poseidon::<Fr>::new();
        let low_nullifier_hash = poseidon.hash_unchecked(vec![
            low_nullifier.node.value,
            Fr::from(low_nullifier.tree_index as u64),
            low_nullifier.node.next_value,
        ]);
        let witness_hash = nullifier_tree
            .non_membership_witness(lifted_nullifiers[0])
            .unwrap()
            .into_iter()
            .enumerate()
            .fold(low_nullifier_hash, |acc, (i, curr)| {
                if low_nullifier.tree_index >> i & 1 == 0 {
                    poseidon.hash_unchecked(vec![acc, curr])
                } else {
                    poseidon.hash(vec![curr, acc]).unwrap()
                }
            });

        let client_input: ClientInput<VestaConfig, 1, 1> = ClientInput {
            proof: transfer_ipa_proof,
            nullifiers: [nullifiers[0]],
            commitments: [transfer_circuits[0].public_input().unwrap()[1]],
            commitment_tree_root: [prev_commitment_tree.root.0],
            path_comm_tree_root_to_global_tree_root: [global_comm_tree
                .membership_witness(0)
                .unwrap()
                .try_into()
                .unwrap()],
            path_comm_tree_index: [Fr::zero()],
            low_nullifier: [low_nullifier.node.clone()],
            low_nullifier_indices: [Fr::from(low_nullifier.tree_index as u64)],
            low_nullifier_mem_path: [nullifier_tree
                .non_membership_witness(lifted_nullifiers[0])
                .unwrap()
                .try_into()
                .unwrap()],
            vk_paths: vk_paths[0].clone().try_into().unwrap(),
            vk_path_index: Fr::from(0u64),
            vk: transfer_ipa_vk.clone(),
            ciphertext: transfer_circuits[0].public_input().unwrap()[2..]
                .try_into()
                .unwrap(),
        };
        // nullifier_tree.append_leaf(lifted_nullifiers[0]);
        nullifier_tree.update_low_nullifier(lifted_nullifiers[0]);
        let low_nullifier = nullifier_tree.find_predecessor(lifted_nullifiers[1]);

        let client_input_2: ClientInput<VestaConfig, 1, 1> = ClientInput {
            proof: transfer_ipa_proof_2,
            nullifiers: [nullifiers[1]],
            commitments: [transfer_circuits[1].public_input().unwrap()[1]],
            commitment_tree_root: [prev_commitment_tree.root.0],
            path_comm_tree_root_to_global_tree_root: [global_comm_tree
                .membership_witness(0)
                .unwrap()
                .try_into()
                .unwrap()],
            path_comm_tree_index: [Fr::zero()],
            low_nullifier: [low_nullifier.node.clone()],
            low_nullifier_indices: [Fr::from(low_nullifier.tree_index as u64)],
            low_nullifier_mem_path: [nullifier_tree
                .non_membership_witness(lifted_nullifiers[1])
                .unwrap()
                .try_into()
                .unwrap()],
            vk_paths: vk_paths[0].clone().try_into().unwrap(),
            vk_path_index: Fr::from(0u64),
            vk: transfer_ipa_vk,
            ciphertext: transfer_circuits[1].public_input().unwrap()[2..]
                .try_into()
                .unwrap(),
        };

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
            base_rollup_circuit::<VestaConfig, PallasConfig, 2, 1, 1>(
                [client_input, client_input_2],
                vk_tree.root.0,
                // initial_nullifier_tree.root,
                witness_hash,
                initial_nullifier_tree.leaf_count.into(),
                global_comm_tree.root.0,
                [g_poly, g_poly_2],
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
        let subtree_pi = SubTrees::from_vec(public_inputs[5..=6].to_vec());
        let instance: AccInstance<VestaConfig> = AccInstance {
            comm: SWPoint(
                public_inputs[7],
                public_inputs[8],
                public_inputs[9] == Fr::one(),
            ),
            // values are originally Vesta scalar => safe switch back into 'native'
            eval: field_switching(&public_inputs[10]),
            eval_point: field_switching(&public_inputs[11]),
        };

        StoredProof {
            proof: base_ipa_proof,
            pub_inputs: (
                global_public_inputs,
                subtree_pi,
                instance,
                vec![],
            ),
            vk: base_ipa_vk,
            commit_key: (pallas_commit_key, vesta_commit_key),
            g_poly,
            pi_stars: (Default::default(), pi_star),
        }
    }
    fn transfer_circuit_helper_generator(
        value: Fq,
        old_sib_path: Vec<Fq>,
        root: Fq,
        old_leaf_index: u64,
    ) -> PlonkCircuit<Fq> {
        let recipient_public_key = Affine::rand(&mut test_rng());
        let ephemeral_key = Fq::rand(&mut test_rng());
        let token_id = Fq::from_str("2").unwrap();
        let root_key = Fq::rand(&mut test_rng());
        let private_key_domain = Fq::from_str("1").unwrap();
        let nullifier_key_domain = Fq::from_str("2").unwrap();

        let token_nonce = Fq::from(3u32);

        let circuit = transfer_circuit::<PallasConfig, VestaConfig, 1, 1, 8>(
            [value],
            [token_nonce],
            [old_sib_path.try_into().unwrap()],
            [Fq::from(old_leaf_index)],
            [root],
            [value],
            [Fq::from(old_leaf_index)],
            token_id,
            recipient_public_key,
            root_key,
            ephemeral_key,
            private_key_domain,
            nullifier_key_domain,
        )
        .unwrap();

        let public_inputs = circuit.public_input().unwrap();
        assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());
        circuit
    }

    fn mint_circuit_helper_generator(value: Fq) -> PlonkCircuit<Fq> {
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let secret_key = Fq::from_str("4").unwrap();
        let secret_key_fr = field_switching::<Fq, Fr>(&secret_key);
        let token_owner = (PallasConfig::GENERATOR * secret_key_fr).into_affine();
        let circuit = mint_circuit::<PallasConfig, VestaConfig, 1>(
            [value],
            [token_id],
            [token_nonce],
            [token_owner],
        )
        .unwrap();

        assert!(circuit
            .check_circuit_satisfiability(&circuit.public_input().unwrap())
            .is_ok());
        circuit
    }

    fn tree_generator(
        vks: Vec<VerifyingKey<VestaConfig>>,
        comms: Vec<Fq>,
        nullifiers: Vec<Fq>,
        global_comm_roots: Vec<Fr>,
    ) -> (
        Tree<Fr, 1>,
        Tree<Fq, 8>,
        IndexedMerkleTree<Fr, 32>,
        Tree<Fr, 8>,
    ) {
        // Vk trees
        let poseidon: Poseidon<Fr> = Poseidon::new();
        let vk_hashes = vks.iter().map(|vk| {
            let vk_sigmas = vk.sigma_comms();
            let vk_selectors = vk.selector_comms();
            let vk_sigma_hashes = vk_sigmas
                .iter()
                .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
            let vk_selector_hashes = vk_selectors
                .iter()
                .map(|v| poseidon.hash_unchecked(vec![v.0.x, v.0.y]));
            let vk_hashes = vk_sigma_hashes
                .chain(vk_selector_hashes)
                .collect::<Vec<_>>();
            let outlier_pair = vk_hashes[0..2].to_vec();
            let mut total_leaves = vk_hashes[2..].to_vec();
            for _ in 0..4 {
                let lefts = total_leaves.iter().step_by(2);
                let rights = total_leaves.iter().skip(1).step_by(2);
                let pairs = lefts.zip(rights);
                total_leaves = pairs
                    .map(|(&x, &y)| poseidon.hash_unchecked(vec![x, y]))
                    .collect::<Vec<_>>();
            }
            poseidon.hash_unchecked(vec![outlier_pair[0], outlier_pair[1], total_leaves[0]])
        });

        let vk_tree: Tree<Fr, 1> = Tree::from_leaves(vk_hashes.collect::<Vec<_>>());

        // commitment trees
        let commitment_tree: Tree<Fq, 8> = Tree::from_leaves(comms);
        // nullifier trees
        let lifted_nullifiers = nullifiers
            .iter()
            .map(field_switching::<Fq, Fr>)
            .collect::<Vec<_>>();
        let nullifier_tree: IndexedMerkleTree<Fr, 32> =
            IndexedMerkleTree::from_leaves(lifted_nullifiers);
        // global root tree
        let global_root_tree: Tree<Fr, 8> = Tree::from_leaves(global_comm_roots);
        (vk_tree, commitment_tree, nullifier_tree, global_root_tree)
    }
}
