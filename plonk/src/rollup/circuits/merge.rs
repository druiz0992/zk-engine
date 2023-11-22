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
    gadgets::{
        ecc::{short_weierstrass::SWPoint, SWToTEConParam},
        from_emulated_field, EmulationConfig,
    },
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::field_switching;

use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonStateVar};

use super::structs::{AccInstance, GlobalPublicInputs, SubTrees};

// C1 is Vesta, C2 is Pallas
//Public Inputs:
//[Commitment Root[0],Vk root[1], nullifier root [2],
// leaf_count[3], verify_acc[4..7], verify_acc_field[7..9], new_nullifier_Root, comm_subtree,
// null_subtree ]
//
#[allow(clippy::too_many_arguments)]
pub fn merge_circuit<C1, C2>(
    // test_pi: Vec<C1::ScalarField>,
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::ScalarField>,
    subtrees: [SubTrees<C2::ScalarField>; 2],
    proof: [Proof<C1>; 2],
    g_poly: [DensePolynomial<C1::ScalarField>; 2],

    // Pass through, we dont do anything with this here
    passthrough_pv_acc: [AccInstance<C2>; 2],

    commit_key: CommitKey<C1>,
    base_accs: [AccInstance<C1>; 2],
    base_pi_stars: [DensePolynomial<C1::ScalarField>; 2],
) -> Result<PlonkCircuit<C2::ScalarField>, CircuitError>
where
    C1: Pairing<G1Affine = Affine<<<C1 as Pairing>::G1 as CurveGroup>::Config>>,
    <<C1 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C1::BaseField>,
    <C1 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C2::ScalarField> + RescueParameter + SWToTEConParam,

    C2: Pairing<
        BaseField = C1::ScalarField,
        ScalarField = C1::BaseField,
        G1Affine = Affine<<<C2 as Pairing>::G1 as CurveGroup>::Config>,
    >,
    <<C2 as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig<BaseField = C2::BaseField>,
    <C2 as Pairing>::BaseField:
        PrimeField + PoseidonParams<Field = C1::ScalarField> + RescueParameter + SWToTEConParam,
    <C2 as Pairing>::ScalarField: EmulationConfig<<C2 as Pairing>::BaseField>,
{
    let mut circuit = PlonkCircuit::<C2::ScalarField>::new_ultra_plonk(8);
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &vk)?;
    let g_gen: SWPoint<C1::BaseField> = vk.open_key.g_bases[0].into();

    let mut instances = vec![];
    let mut g_comms_vars = vec![];
    let mut u_challenges_vars = vec![];
    let mut eval_vars = vec![];
    let mut g_polys = vec![];
    // Build Bounce Instances and PV
    for i in 0..2 {
        let proof_var = PlonkIpaSWProofNativeVar::create_variables(&mut circuit, &proof[i])?;

        // =======================================================
        // Base acc:
        // = previously completed Vesta acc
        // It is used as a public input for bounce i PV (it was the passthrough instance there)
        // And to acc later in this circuit
        let instance = base_accs[i].clone().into();
        instances.push(instance);

        let sw_point_var = circuit.create_sw_point_variable(base_accs[i].comm)?;
        let value = circuit.create_variable(field_switching(&base_accs[i].eval))?;
        let point = circuit.create_variable(field_switching(&base_accs[i].eval_point))?;
        g_comms_vars.push(sw_point_var);
        u_challenges_vars.push(point);
        eval_vars.push(value);
        g_polys.push(base_pi_stars[i].clone());

        // =======================================================
        // Public inputs for bounce i PV

        let mut bounce_public_inputs = global_state.to_vec();
        let subtree_public_inputs = subtrees[i].to_vec();
        bounce_public_inputs.extend(subtree_public_inputs);

        // we push base acc first (it was the passthrough of bounce)
        let base_acc_public_inputs: Vec<C2::ScalarField> = base_accs[i].to_vec();
        bounce_public_inputs.extend(base_acc_public_inputs);

        // we convert to 'emulated' since that what bounce takes in
        // TODO: something else
        let mut bounce_public_inputs_var: Vec<Variable> = bounce_public_inputs
            .iter()
            .map(|&x| {
                let limb_x: Vec<_> = from_emulated_field(x);
                let limb_x_vars: Vec<Variable> = limb_x
                    .into_iter()
                    .map(|l_x| {
                        // for_testing.push(l_x);
                        circuit.create_variable(field_switching(&l_x))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let recombined_x: Variable =
                    circuit.recombine_limbs(&limb_x_vars, <C2 as Pairing>::ScalarField::B)?;
                circuit.set_variable_public(recombined_x)?;
                // assert_eq!(x, circuit.witness(recombined_x)?, "NOT EQUAL ");
                Ok(limb_x_vars)
            })
            .collect::<Result<Vec<_>, CircuitError>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        // we push passthrough last (it was the PV result at the end of bounce)
        bounce_public_inputs_var.push(
            circuit.create_public_variable(field_switching(&passthrough_pv_acc[i].comm.get_x()))?,
        );
        bounce_public_inputs_var.push(
            circuit.create_public_variable(field_switching(&passthrough_pv_acc[i].comm.get_y()))?,
        );
        bounce_public_inputs_var.push(
            circuit
                .create_public_boolean_variable(passthrough_pv_acc[i].comm.get_inf())?
                .into(),
        );
        bounce_public_inputs_var.push(0);
        circuit.create_public_variable(C1::BaseField::from(0u64))?;
        // u-var of bounce was emulated
        let emul_point = from_emulated_field(field_switching::<_, C1::BaseField>(
            &passthrough_pv_acc[i].eval_point,
        ));
        let emul_point_limb_vars = emul_point
            .iter()
            .map(|l_x| circuit.create_variable(field_switching(l_x)))
            .collect::<Result<Vec<_>, _>>()?;
        let recombined_point = circuit.recombine_limbs(&emul_point_limb_vars, C1::BaseField::B)?;
        circuit.set_variable_public(recombined_point)?;
        emul_point_limb_vars
            .into_iter()
            .for_each(|l| bounce_public_inputs_var.push(l));

        // let test_pi_vars = test_pi
        //     .iter()
        //     .map(|x| circuit.create_variable(field_switching(x)))
        //     .collect::<Result<Vec<_>, _>>()?;

        // =======================================================
        // PV of bounce i:
        // we don't set to public, because we acc with base_acc in this circuit, and set that to public instead
        let (g_comm_var, u_challenge_var) = &verifying_key_var.partial_verify_circuit_ipa_native(
            &mut circuit,
            &g_gen,
            &bounce_public_inputs_var,
            &proof_var,
        )?;

        let u_challenge_fq = circuit.witness(*u_challenge_var)?;
        let u_challenge = field_switching::<C1::BaseField, C1::ScalarField>(&u_challenge_fq);
        let instance = PCSInstance::<UnivariateIpaPCS<C1>>::new(
            Commitment(circuit.sw_point_witness(g_comm_var)?.into()),
            C2::BaseField::from(0u64),
            u_challenge,
        );
        instances.push(instance);
        g_comms_vars.push(*g_comm_var);
        u_challenges_vars.push(*u_challenge_var);
        // single PV'd proof => eval is 0
        eval_vars.push(circuit.zero());
        g_polys.push(g_poly[i].clone());
        // =======================================================
    }

    // Partial prove accumulation of all instances
    let prover = AccProver::new();
    // 1 SW Point + 2 Field element made public here
    let (acc, _) = prover
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
        &g_comms_vars,
        &eval_vars,
        &u_challenges_vars,
        &acc,
    )?;

    // Rollup subtrees
    // Commitment subtree
    // TODO use existing var
    let left_subtree_var = circuit.create_variable(subtrees[0].commitment_subtree)?;
    let right_subtree_var = circuit.create_variable(subtrees[1].commitment_subtree)?;
    let commitment_subtree = PoseidonGadget::<PoseidonStateVar<3>, C2::ScalarField>::hash(
        &mut circuit,
        [left_subtree_var, right_subtree_var].as_slice(),
    )?;
    circuit.set_variable_public(commitment_subtree)?;
    // Nullifier subtree
    let left_subtree_var = circuit.create_variable(subtrees[0].nullifier_subtree)?;
    let right_subtree_var = circuit.create_variable(subtrees[1].nullifier_subtree)?;
    let nullifier_subtree = PoseidonGadget::<PoseidonStateVar<3>, C2::ScalarField>::hash(
        &mut circuit,
        [left_subtree_var, right_subtree_var].as_slice(),
    )?;
    circuit.set_variable_public(nullifier_subtree)?;

    Ok(circuit)
}

#[cfg(test)]
pub mod merge_test {

    use crate::rollup::circuits::{
        bounce::bounce_test::bounce_test_helper, merge::merge_circuit, utils::StoredProof,
    };
    use ark_ec::pairing::Pairing;
    use curves::{pallas::PallasConfig, vesta::VestaConfig};
    use jf_plonk::{
        nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
    };
    use jf_relation::{Arithmetization, Circuit};
    use jf_utils::{field_switching, test_rng};

    #[test]
    fn merge_test() {
        merge_test_helper();
    }
    fn merge_test_helper() {
        ark_std::println!("Running file read");
        // let str = std::fs::File::open("bounce_proof.json").unwrap();
        // let stored_bounce: StoredProof<VestaConfig> = serde_json::from_reader(str).unwrap();
        let (bounce_circuit, stored_bounce) = bounce_test_helper();
        let stored_bounce_2 = stored_bounce.clone();
        let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
            stored_bounce.pub_inputs;
        let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;

        let mut rng = test_rng();

        let mut merge_circuit = merge_circuit::<VestaConfig, PallasConfig>(
            // bounce_circuit.public_input().unwrap(),
            stored_bounce.vk,
            global_public_inputs,
            [subtree_pi_1, subtree_pi_2],
            [stored_bounce.proof, stored_bounce_2.proof],
            [stored_bounce.g_poly, stored_bounce_2.g_poly],
            [passthrough_instance_1, passthrough_instance_2],
            stored_bounce.commit_key.1,
            [instance_1[0].clone(), instance_2[0].clone()],
            [stored_bounce.pi_stars.1, stored_bounce_2.pi_stars.1],
        )
        .unwrap();
        merge_circuit
            .check_circuit_satisfiability(&merge_circuit.public_input().unwrap())
            .unwrap();
        merge_circuit.finalize_for_arithmetization().unwrap();
        let merge_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            merge_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (merge_ipa_pk, merge_ipa_vk) =
            PlonkIpaSnark::<PallasConfig>::preprocess(&merge_ipa_srs, &merge_circuit).unwrap();
        let now = std::time::Instant::now();
        let merge_ipa_proof = PlonkIpaSnark::<PallasConfig>::prove::<
            _,
            _,
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(&mut rng, &merge_circuit, &merge_ipa_pk, None)
        .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<PallasConfig>::verify::<
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(
            &merge_ipa_vk,
            &merge_circuit.public_input().unwrap(),
            &merge_ipa_proof,
            None,
        )
        .unwrap();
        ark_std::println!("Proof verified")
    }
}
