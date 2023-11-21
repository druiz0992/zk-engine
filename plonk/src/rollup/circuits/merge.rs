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
    Circuit, PlonkCircuit,
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
    test_pi: Vec<C1::ScalarField>,
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::ScalarField>,
    subtrees: [SubTrees<C2::ScalarField>; 2],
    proof: [Proof<C1>; 2],
    g_poly: [DensePolynomial<C1::ScalarField>; 2],

    // Pass through, we dont do anything with this here
    passthrough_pv_acc: [AccInstance<C2::BaseField>; 2],

    commit_key: CommitKey<C1>,
    base_accs: [AccInstance<C2::ScalarField>; 2],
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

        // Passthrough of bounce, previously from base
        ark_std::println!("x coordinate: {}", base_accs[i].comm.0);
        let instance = base_accs[i].clone().into();

        instances.push(instance);

        let sw_point_var = circuit.create_sw_point_variable(base_accs[i].comm)?;
        let value = circuit.create_variable(base_accs[i].eval)?;
        let point = circuit.create_variable(base_accs[i].eval_point)?;
        g_comms_vars.push(sw_point_var);
        u_challenges_vars.push(point);
        eval_vars.push(value);
        g_polys.push(base_pi_stars[i].clone());

        let mut bounce_public_inputs = global_state.to_vec();
        let subtree_public_inputs = subtrees[i].to_vec();
        bounce_public_inputs.extend(subtree_public_inputs);

        let passthrough_public_inputs: Vec<C2::ScalarField> = passthrough_pv_acc[i].to_vec_switch();
        bounce_public_inputs.extend(passthrough_public_inputs);

        let mut for_testing = vec![];
        let mut bounce_public_inputs_var = bounce_public_inputs
            .iter()
            .flat_map(|&x| {
                let limb_x = from_emulated_field(x);
                limb_x
                    .into_iter()
                    .map(|l_x| {
                        for_testing.push(l_x);
                        circuit.create_variable(field_switching(&l_x))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Result<Vec<_>, _>>()?;

        for (i, &test) in for_testing.iter().enumerate() {
            ark_std::println!("{}: {}  |  {}", i, test, test_pi[i]);
            assert_eq!(test, test_pi[i], "SOMETHING NOT EQUL")
        }

        bounce_public_inputs_var.push(sw_point_var.get_x());
        bounce_public_inputs_var.push(sw_point_var.get_y());
        bounce_public_inputs_var.push(circuit.false_var().into());
        bounce_public_inputs_var.push(value);
        let emul_point = from_emulated_field(base_accs[i].eval_point);
        emul_point.iter().for_each(|l_x| {
            bounce_public_inputs_var.push(circuit.create_variable(field_switching(l_x)).unwrap())
        });

        for i in (for_testing.len() - 1)..bounce_public_inputs_var.len() {
            ark_std::println!(
                "{}: {}  |  {}",
                i,
                circuit.witness(bounce_public_inputs_var[i]).unwrap(),
                test_pi[i]
            );
            //     assert_eq!(
            //         test_pi[i],
            //         field_switching(&circuit.witness(bounce_public_inputs_var[i]).unwrap()),
            //         "SOMETHING NOT EQUAL {}",
            //         i
            //     )
        }
        bounce_public_inputs_var.push(point);
        ark_std::println!(
            "Bounce Public Inputs Var len: {:?}",
            bounce_public_inputs_var.len()
        );

        let test_pi_vars = test_pi
            .iter()
            .map(|x| circuit.create_variable(field_switching(x)))
            .collect::<Result<Vec<_>, _>>()?;
        let (g_comm_var, u_challenge_var) = &verifying_key_var.partial_verify_circuit_ipa_native(
            &mut circuit,
            &g_gen,
            &test_pi_vars,
            // &bounce_public_inputs_var,
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
        eval_vars.push(circuit.zero());
        g_polys.push(g_poly[i].clone());
    }

    // Partial prove accumulation of all instances
    let prover = AccProver::new();
    // 1 SW Point + 2 Field element made public here
    let (acc, _) = prover
        .prove_accumulation(
            &commit_key,
            &[instances[1].clone(), instances[3].clone()],
            &[g_polys[1].clone(), g_polys[3].clone()],
        )
        .unwrap();

    verify_accumulation_gadget_sw_native::<
        C1,
        C2,
        _,
        _,
        <<C1 as Pairing>::G1 as CurveGroup>::Config,
    >(
        &mut circuit,
        &[g_comms_vars[1], g_comms_vars[3]],
        &[eval_vars[1], eval_vars[3]],
        &[u_challenges_vars[1], u_challenges_vars[3]],
        // &g_comms_vars.as_slice(),
        // &eval_vars.as_slice(),
        // &u_challenges_vars.as_slice(),
        &acc,
    )?;

    // Rollup subtrees
    // Commitment subtree
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
        // let mut bounce_public_inputs = global_public_inputs.to_vec();
        // let subtree_public_inputs = subtree_pi_1.to_vec();
        // bounce_public_inputs.extend(subtree_public_inputs);
        // let mut verify_pi = bounce_public_inputs
        //     .into_iter()
        //     .map(|x| field_switching(&x))
        //     .collect::<Vec<_>>();
        //
        // let passthrough_public_inputs: Vec<_> = passthrough_instance_1.to_vec();
        // verify_pi.extend(passthrough_public_inputs);
        // PlonkIpaSnark::<VestaConfig>::verify::<
        //     RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        // >(
        //     &stored_bounce.vk,
        //     &verify_pi,
        //     &stored_bounce.proof,
        //     None,
        // )
        // .unwrap();

        ark_std::println!("VERIFY BOUNCE IN MERGE!, PIs are good");
        ark_std::println!("instance 1: {}", instance_1[0].comm.0);
        ark_std::println!("instance 2: {}", instance_2[0].comm.0);

        let mut merge_circuit = merge_circuit::<VestaConfig, PallasConfig>(
            bounce_circuit.public_input().unwrap(),
            stored_bounce.vk,
            global_public_inputs,
            [subtree_pi_1, subtree_pi_2],
            [stored_bounce.proof, stored_bounce_2.proof],
            [stored_bounce.g_poly, stored_bounce_2.g_poly],
            [
                passthrough_instance_1.switch_field(),
                passthrough_instance_2.switch_field(),
            ],
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
