use crate::primitives::circuits::{
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};
use crate::rollup::circuits::client_input::ClientInput;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::{
    circuit::plonk_partial_verifier::SWVerifyingKeyVar, ipa_structs::VerifyingKey,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{
    errors::CircuitError, gadgets::ecc::SWToTEConParam, Circuit, PlonkCircuit, Variable,
};
use jf_utils::{field_switching, fr_to_fq};

#[allow(dead_code)]
pub enum BasePublicVarIndex {
    GlobalCommitmentRoot = 0,
    GlobaVkRoot = 1,
    GlobalNullifierRoot = 2,
    GlobalNullifierLeafCount = 3,
    NullifierNewCount = 4,
    CommitmentSubteeRoot = 5,
    NullifierSubtreeRoot = 6,
    AccumulatorCommitmentX = 7,
    AccumulatorCommitmentY = 8,
    AccumulatorInstanceValue = 9,
    AccumulatorInstancePoint = 10,
}

pub(super) fn create_initial_low_nullifier_vars<C1, const D: usize>(
    circuit: &mut PlonkCircuit<<C1 as Pairing>::BaseField>,
    client_inputs: &ClientInput<C1, D>,
) -> Result<[usize; 3], CircuitError>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
{
    let initial_low_nullifier_value =
        circuit.create_variable(field_switching(&client_inputs.nullifiers[0]))?;
    let initial_low_nullifier_next_index =
        circuit.create_variable(client_inputs.low_nullifier[0].next_index().into())?;
    let initial_low_nullifier_next_value =
        circuit.create_variable(field_switching(&client_inputs.nullifiers[0]))?;
    Ok([
        initial_low_nullifier_value,
        initial_low_nullifier_next_index,
        initial_low_nullifier_next_value,
    ])
}

pub(super) fn hash_verification_key<C1, C2, const D: usize>(
    circuit: &mut PlonkCircuit<<C1 as Pairing>::BaseField>,
    vk: &VerifyingKey<C1>,
) -> Result<(SWVerifyingKeyVar<C1>, usize), CircuitError>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
    <C1 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C2::ScalarField> + RescueParameter + SWToTEConParam,

    C2: Pairing<BaseField = C1::ScalarField, ScalarField = C1::BaseField>,
{
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(circuit, vk)?;
    // This vec, first 10 elements are sigma_comms
    let verifying_key_var_vec = verifying_key_var.to_vec();
    let sigma_comms = verifying_key_var_vec[0..10].to_vec();
    let sigma_comms_pairs = sigma_comms
        .iter()
        .step_by(2)
        .zip(sigma_comms.iter().skip(1).step_by(2));
    let mut sigma_hashes_leaves = sigma_comms_pairs
        .map(|(&x, &y)| {
            PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(circuit, [x, y].as_slice())
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
            PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(circuit, [x, y].as_slice())
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
                    circuit,
                    [x, y].as_slice(),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
    }
    // The is the final hash of the outliers and the root of the mini tree
    let vk_var_hash = PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(
        circuit,
        [outlier_pair.0, outlier_pair.1, total_leaves[0]].as_slice(),
    )?;

    Ok((verifying_key_var, vk_var_hash))
}

pub(super) fn poseidon_gadget<C1, C2>(
    circuit: &mut PlonkCircuit<<C1 as Pairing>::BaseField>,
    inputs: &[Variable],
    C: usize,
) -> Result<usize, CircuitError>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
    <C1 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C2::ScalarField> + RescueParameter + SWToTEConParam,

    C2: Pairing<BaseField = C1::ScalarField, ScalarField = C1::BaseField>,
{
    let hash = match C {
        2 => PoseidonGadget::<PoseidonStateVar<3>, C1::BaseField>::hash(circuit, inputs)?,
        3 => PoseidonGadget::<PoseidonStateVar<4>, C1::BaseField>::hash(circuit, inputs)?,
        4 => PoseidonGadget::<PoseidonStateVar<5>, C1::BaseField>::hash(circuit, inputs)?,
        6 => PoseidonGadget::<PoseidonStateVar<7>, C1::BaseField>::hash(circuit, inputs)?,
        8 => PoseidonGadget::<PoseidonStateVar<9>, C1::BaseField>::hash(circuit, inputs)?,
        _ => {
            return Err(CircuitError::ParameterError(
                "Incorrect PoseidonStateVar".to_string(),
            ))
        }
    };
    Ok(hash)
}

pub(super) fn client_commitment_membership_check<C1, C2, const D: usize>(
    circuit: &mut PlonkCircuit<<C1 as Pairing>::BaseField>,
    input: &ClientInput<C1, D>,
    global_commitment_root_var: usize,
    idx: usize,
) -> Result<(usize, usize), CircuitError>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
    <C1 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C2::ScalarField> + RescueParameter + SWToTEConParam,

    C2: Pairing<BaseField = C1::ScalarField, ScalarField = C1::BaseField>,
{
    let commitment_tree_root_fq = fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(
        &input.commitment_tree_root[idx],
    );
    let commitment_tree_root_var = circuit.create_variable(commitment_tree_root_fq)?;
    let calc_commitment_root_var =
        // This <8> is the depth of the block level commitment tree
        BinaryMerkleTreeGadget::<D, C1::BaseField>::calculate_root(
            circuit,
            commitment_tree_root_var,
            input.path_comm_tree_index[idx],
            input.path_comm_tree_root_to_global_tree_root[idx],
        )?;

    // Nullifiers are in Vesta Fr and are safely lifted to this Pallas Fr (which is Vesta Fq)
    let nullifier_fq =
        fr_to_fq::<_, <<C1 as Pairing>::G1 as CurveGroup>::Config>(&input.nullifiers[idx]);
    let nullifier = circuit.create_variable(nullifier_fq)?; // OUT
                                                            // Conditional check if nullifier is zero
    let nullifier_is_zero = circuit.is_zero(nullifier)?;
    // If the nullifier is zero, then we need to trivially pass the root check
    let calc_commitment_root_select = circuit.conditional_select(
        nullifier_is_zero,
        calc_commitment_root_var,
        global_commitment_root_var,
    )?;
    circuit.enforce_equal(calc_commitment_root_select, global_commitment_root_var)?;

    Ok((commitment_tree_root_var, nullifier))
}
