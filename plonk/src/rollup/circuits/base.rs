use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
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
    Circuit, PlonkCircuit,
};
use jf_utils::{field_switching, fr_to_fq};
use trees::non_membership_tree::IndexedNode;

use crate::primitives::circuits::{
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};

// Fixed constants - I: Number of Input proofs (assume 2)
// C: number of commitments, N: number of nullifiers
pub struct ClientInput<E, const C: usize, const N: usize>
where
    E: Pairing,
    <<E as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = E::BaseField>,
{
    proof: Proof<E>,
    nullifiers: [E::ScalarField; N], // List of nullifiers in transaction
    commitments: [E::ScalarField; C], // List of commitments in transaction
    commitment_tree_root: E::ScalarField, // Tree root for comm membership
    path_comm_tree_root_to_global_tree_root: [E::BaseField; 8],
    path_comm_tree_index: E::BaseField,
    low_nullifier: [IndexedNode<E::BaseField>; N],
    low_nullifier_indices: [E::BaseField; N],
    low_nullifier_mem_path: [[E::BaseField; 32]; N], // Path for nullifier non membership
    vk_paths: [E::BaseField; 2],
    vk_path_index: E::BaseField,
    vk: VerifyingKey<E>,
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
    let mut instances = vec![];
    let mut g_comms_vars = vec![];
    let mut u_challenges_vars = vec![];
    let mut leaf_hashes = vec![];
    let mut nullifier_leaf_hashes = vec![];
    let mut nullifier_new_root = circuit.create_public_variable(global_nullifier_root)?;
    for input in client_inputs {
        // Step 1: Hash verification keys
        let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &input.vk)?;
        let verifying_key_var_vec = verifying_key_var.to_vec(); // Todo come back to check this
                                                                // What is the length of this hash?
        let vk_var_hash = PoseidonGadget::<PoseidonStateVar<6>, C1::BaseField>::hash(
            &mut circuit,
            verifying_key_var_vec.as_slice(),
        )?;

        // Step 2: Check set membership of H(vk_i)
        let calc_vk_root_var = BinaryMerkleTreeGadget::<2, C1::BaseField>::calculate_root(
            &mut circuit,
            vk_var_hash,
            input.vk_path_index,
            input.vk_paths,
        )?;
        let global_vk_root_var = circuit.create_public_variable(global_vk_root)?;
        circuit.enforce_equal(calc_vk_root_var, global_vk_root_var)?;

        // Step 3: Check commitment_tree_roots are in global_commitment_root
        let commitment_tree_root_fq =
            fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(&input.commitment_tree_root);
        let commitment_tree_root_var = circuit.create_public_variable(commitment_tree_root_fq)?;
        let calc_commitment_root_var = BinaryMerkleTreeGadget::<8, C1::BaseField>::calculate_root(
            &mut circuit,
            commitment_tree_root_var,
            input.path_comm_tree_index,
            input.path_comm_tree_root_to_global_tree_root,
        )?;
        let global_commitment_root_var = circuit.create_public_variable(global_commitment_root)?;
        circuit.enforce_equal(calc_commitment_root_var, global_commitment_root_var)?;
        // Step 4: Check nullifier is "step over" of low_nullifier
        // If the next_value &  next_index in low nullifier == 0, then check nullifier.value >
        // low_null.value (Max condition)
        let mut input_nullifier_hashes = vec![];
        for i in 0..N {
            let low_nullifer_next_value_var =
                circuit.create_variable(input.low_nullifier[i].next_value)?;
            let low_nullifier_next_index_var = circuit.create_variable(C1::BaseField::from(
                input.low_nullifier[i].next_index as u64,
            ))?;
            let low_nullifier_next_value_is_zero = circuit.is_zero(low_nullifer_next_value_var)?;
            let low_nullifier_next_index_is_zero = circuit.is_zero(low_nullifier_next_index_var)?;
            let max_condition_next_are_zero = circuit.logic_and(
                low_nullifier_next_value_is_zero,
                low_nullifier_next_index_is_zero,
            )?;
            let low_nullifier_value_var = circuit.create_variable(input.low_nullifier[i].value)?;
            let nullifier_fq =
                fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(&input.nullifiers[i]);
            let nullifier = circuit.create_variable(nullifier_fq)?;
            let low_nullifier_value_max = circuit.is_lt(low_nullifier_value_var, nullifier)?;
            let max_condition =
                circuit.logic_and(max_condition_next_are_zero, low_nullifier_value_max)?;

            // In not MAX condition, we check the low nullifier is a "step over"
            let next_value_gt_nullifier = circuit.is_gt(low_nullifer_next_value_var, nullifier)?;
            let low_nullifer_value_lt_nullifier =
                circuit.is_lt(nullifier, low_nullifier_value_var)?;
            let sandwich_condition =
                circuit.logic_and(next_value_gt_nullifier, low_nullifer_value_lt_nullifier)?;
            let condition_met = circuit.logic_or(max_condition, sandwich_condition)?;
            circuit.enforce_true(condition_met.into())?; // this is weird

            // Step 4.5: Check low_nullifier set membership in global_nullifier_root
            let low_nullifier_hash = PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
                &mut circuit,
                [
                    low_nullifier_value_var,
                    low_nullifier_next_index_var,
                    low_nullifer_next_value_var,
                ]
                .as_slice(),
            )?;
            let nullifier_tree_root_var = circuit.create_public_variable(global_nullifier_root)?;
            let calc_nullifier_root_var =
                BinaryMerkleTreeGadget::<32, C1::BaseField>::calculate_root(
                    &mut circuit,
                    low_nullifier_hash,
                    input.low_nullifier_indices[i],
                    input.low_nullifier_mem_path[i],
                )?;
            circuit.enforce_equal(nullifier_tree_root_var, calc_nullifier_root_var)?;
            let leaf_count = circuit.create_public_variable(global_nullifier_leaf_count)?;
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
            input_nullifier_hashes.push(new_inserted_nullifier);
            // Step 8: Hash the input  nullifiers pairwise
            // Use low nullifier mem path but with new hash
            nullifier_new_root = BinaryMerkleTreeGadget::<32, C1::BaseField>::calculate_root(
                &mut circuit,
                new_low_nullifier_hash,
                input.low_nullifier_indices[i],
                input.low_nullifier_mem_path[i],
            )?;
        }
        // Step 5: PV each input proof
        let proof_var = PlonkIpaSWProofNativeVar::create_variables(&mut circuit, &input.proof)?;
        let g_gen: SWPoint<C1::BaseField> = input.vk.open_key.g_bases[0].into();
        let (g_comm_var, u_challenge_var) = &verifying_key_var.partial_verify_circuit_ipa_native(
            &mut circuit,
            &g_gen,
            &[], // Come back to this
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
        let commitments_fq = input
            .commitments
            .iter() // C
            .map(fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>)
            .collect::<Vec<_>>();
        let commitments_var = commitments_fq
            .into_iter()
            .map(|x| circuit.create_variable(x))
            .collect::<Result<Vec<_>, _>>()?;
        let subtree_leaf = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
            &mut circuit,
            commitments_var.as_slice(),
        )?;
        leaf_hashes.push(subtree_leaf);

        circuit.set_variable_public(nullifier_new_root)?;
        let nullifier_subtree_leaf = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
            &mut circuit,
            input_nullifier_hashes.as_slice(),
        )?;
        nullifier_leaf_hashes.push(nullifier_subtree_leaf);
    }

    let prover = AccProver::new();
    let (acc, pi_star) = prover
        .prove_accumulation(&commit_key, &instances, &g_polys)
        .unwrap();

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
    // Bag the roots of the subtrees created previously assuming I == 2
    let commitment_subtree_root = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
        &mut circuit,
        leaf_hashes.as_slice(),
    )?;
    circuit.set_variable_public(commitment_subtree_root)?;

    // Bag the roots of the nullifier subtrees created previously assuming I == 2
    let nullifier_subtree_root = PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(
        &mut circuit,
        nullifier_leaf_hashes.as_slice(),
    )?;
    circuit.set_variable_public(nullifier_subtree_root)?;
    Ok((circuit, pi_star))
}
