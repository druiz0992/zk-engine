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
        ecc::{
            short_weierstrass::{SWPoint, SWPointVariable},
            SWToTEConParam,
        },
        from_emulated_field, EmulationConfig,
    },
    Circuit, PlonkCircuit, Variable,
};
use jf_utils::field_switching;

use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonStateVar};

use super::{
    structs::{AccInstance, GlobalPublicInputs, SubTrees},
    utils::enforce_limb_decomposition,
};

// C1 is Vesta, C2 is Pallas

#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub fn merge_circuit<C1, C2>(
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

    // Build one set of public global state vars to compare each bounce PV against
    let global_state_vars: Vec<Variable> = global_state
        .to_vec()
        .iter()
        .map(|val| circuit.create_public_variable(*val))
        .collect::<Result<Vec<_>, CircuitError>>()?;
    // Build two sets of private subtree variables
    // [comm, null], [comm, null]
    let mut subtree_vars = [[0, 0], [0, 0]];

    // Build Bounce Instances and PV
    for i in 0..2 {
        let proof_var = PlonkIpaSWProofNativeVar::create_variables(&mut circuit, &proof[i])?;

        // =======================================================
        // Public inputs for bounce i PV

        let mut bounce_public_inputs_var = vec![];
        // global state
        for (j, val) in global_state.to_vec().iter().enumerate() {
            let (limb_vars, val_var): (Vec<Variable>, Variable) =
                enforce_limb_decomposition::<C2>(&mut circuit, val)?;
            // C2::scalar -> limbs of C2::base
            // let limbed_val: Vec<C2::BaseField> = from_emulated_field(*val);
            // // limbs of C2::base -> values of C2::scalar -> variables
            // let limb_vars: Vec<Variable> = limbed_val
            //     .into_iter()
            //     .map(|l_x| circuit.create_variable(field_switching(&l_x)))
            //     .collect::<Result<Vec<_>, _>>()?;
            // let recombined_var: Variable =
            //     circuit.recombine_limbs(&limb_vars, <C2 as Pairing>::ScalarField::B)?;
            circuit.enforce_equal(val_var, global_state_vars[j])?;
            bounce_public_inputs_var.extend(limb_vars);
        }

        // subtrees
        for (j, val) in subtrees[i].to_vec().iter().enumerate() {
            let (limb_vars, val_var): (Vec<Variable>, Variable) =
                enforce_limb_decomposition::<C2>(&mut circuit, val)?;

            // C2::scalar -> limbs of C2::base
            // let limbed_val: Vec<C2::BaseField> = from_emulated_field(*val);
            // // limbs of C2::base -> values of C2::scalar -> variables
            // let limb_vars: Vec<Variable> = limbed_val
            //     .into_iter()
            //     .map(|l_x| circuit.create_variable(field_switching(&l_x)))
            //     .collect::<Result<Vec<_>, _>>()?;
            subtree_vars[i][j] = val_var;
            // assert_eq!(val, circuit.witness(recombined_var)?, "NOT EQUAL - subtree");
            bounce_public_inputs_var.extend(limb_vars);
        }

        // =======================================================
        // Base acc:
        // = previously completed Vesta acc
        // It is used as a public input for bounce i PV (it was the passthrough instance there)
        // And to acc later in this circuit
        let instance = base_accs[i].clone().into();
        instances.push(instance);

        // we push base acc first (it was the passthrough of bounce)
        let base_acc_vars = base_accs[i].to_vars(&mut circuit)?;
        for (j, val) in base_accs[i].to_vec().iter().enumerate() {
            let (limb_vars, val_var): (Vec<Variable>, Variable) =
                enforce_limb_decomposition::<C2>(&mut circuit, val)?;

            // C2::scalar -> limbs of C2::base
            // let limbed_val: Vec<C2::BaseField> = from_emulated_field(*val);
            // // limbs of C2::base -> values of C2::scalar -> variables
            // let limb_vars: Vec<Variable> = limbed_val
            //     .into_iter()
            //     .map(|l_x| circuit.create_variable(field_switching(&l_x)))
            //     .collect::<Result<Vec<_>, _>>()?;
            // let recombined_var: Variable =
            //     circuit.recombine_limbs(&limb_vars, <C2 as Pairing>::ScalarField::B)?;
            circuit.enforce_equal(val_var, base_acc_vars[j])?;
            // assert_eq!(val, circuit.witness(recombined_var)?, "NOT EQUAL - global state");
            bounce_public_inputs_var.extend(limb_vars);
        }
        g_comms_vars.push(SWPointVariable::new(base_acc_vars[0], base_acc_vars[1]));
        u_challenges_vars.push(base_acc_vars[3]);
        eval_vars.push(base_acc_vars[2]);
        g_polys.push(base_pi_stars[i].clone());

        // we push passthrough last (it was the PV result at the end of bounce)
        bounce_public_inputs_var.push(
            circuit.create_public_variable(field_switching(&passthrough_pv_acc[i].comm.get_x()))?,
        );
        bounce_public_inputs_var.push(
            circuit.create_public_variable(field_switching(&passthrough_pv_acc[i].comm.get_y()))?,
        );

        let emul_val = from_emulated_field(field_switching::<_, C1::BaseField>(
            &passthrough_pv_acc[i].eval,
        ));
        let emul_val_limb_vars = emul_val
            .iter()
            .map(|l_x| circuit.create_variable(field_switching(l_x)))
            .collect::<Result<Vec<_>, _>>()?;
        let recombined_values = circuit.recombine_limbs(&emul_val_limb_vars, C1::BaseField::B)?;
        circuit.set_variable_public(recombined_values)?;
        emul_val_limb_vars
            .into_iter()
            .for_each(|l| bounce_public_inputs_var.push(l));

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
    let (acc, pi_star_out) = prover
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
    let left_subtree_var = subtree_vars[0][0];
    let right_subtree_var = subtree_vars[1][0];
    let commitment_subtree = PoseidonGadget::<PoseidonStateVar<3>, C2::ScalarField>::hash(
        &mut circuit,
        [left_subtree_var, right_subtree_var].as_slice(),
    )?;
    circuit.set_variable_public(commitment_subtree)?;
    // Nullifier subtree
    let left_subtree_var = subtree_vars[0][1];
    let right_subtree_var = subtree_vars[1][1];
    let nullifier_subtree = PoseidonGadget::<PoseidonStateVar<3>, C2::ScalarField>::hash(
        &mut circuit,
        [left_subtree_var, right_subtree_var].as_slice(),
    )?;
    circuit.set_variable_public(nullifier_subtree)?;
    circuit.check_circuit_satisfiability(&circuit.public_input()?)?;
    circuit.finalize_for_arithmetization()?;

    Ok((circuit, pi_star_out))
}

#[cfg(test)]
pub mod merge_test {
    /*

    use crate::rollup::circuits::{
        bounce::bounce_test::bounce_test_helper,
        bounce_merge::bounce_merge_test::bounce_merge_test_helper,
        merge::merge_circuit,
        structs::{AccInstance, SubTrees},
        utils::StoredProof,
    };
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;
    use curves::{
        pallas::PallasConfig,
        vesta::{Fq, VestaConfig},
    };
    use jf_plonk::{
        nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
    };
    use jf_relation::{gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit};
    use jf_utils::{field_switching, test_rng};

    #[test]
    #[ignore]
    pub fn merge_test() {
        let stored_bounce = bounce_test_helper();
        merge_test_helper(stored_bounce);
    }

    #[test]
    pub fn merge_bounce_test() {
        let stored_bounce = bounce_test_helper();
        let stored_merge = merge_test_helper(stored_bounce);
        let stored_bounce_merge = bounce_merge_test_helper(stored_merge);
        merge_test_helper(stored_bounce_merge);
    }
    pub fn merge_test_helper(
        stored_bounce: StoredProof<VestaConfig, PallasConfig>,
    ) -> StoredProof<PallasConfig, VestaConfig> {
        let stored_bounce_2 = stored_bounce.clone();
        let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
            stored_bounce.pub_inputs;
        let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;

        let mut rng = test_rng();

        let (mut merge_circuit, pi_star_out) = merge_circuit::<VestaConfig, PallasConfig>(
            stored_bounce.vk,
            global_public_inputs.clone(),
            [subtree_pi_1, subtree_pi_2],
            [stored_bounce.proof, stored_bounce_2.proof],
            [stored_bounce.g_poly, stored_bounce_2.g_poly],
            [
                passthrough_instance_1.clone(),
                passthrough_instance_2.clone(),
            ],
            stored_bounce.commit_key.1.clone(),
            [instance_1[0].clone(), instance_2[0].clone()],
            [stored_bounce.pi_stars.1, stored_bounce_2.pi_stars.1],
        )
        .unwrap();
        merge_circuit
            .check_circuit_satisfiability(&merge_circuit.public_input().unwrap())
            .unwrap();
        ark_std::println!("Merge circuit constraints: {}", merge_circuit.num_gates());
        merge_circuit.finalize_for_arithmetization().unwrap();
        let merge_ipa_srs = <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            merge_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (merge_ipa_pk, merge_ipa_vk) =
            PlonkIpaSnark::<PallasConfig>::preprocess(&merge_ipa_srs, &merge_circuit).unwrap();
        let all_pi = merge_circuit.public_input().unwrap();
        let now = std::time::Instant::now();
        let (merge_ipa_proof, g_poly, _) = PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
            _,
            _,
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(&mut rng, &merge_circuit, &merge_ipa_pk, None)
        .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<PallasConfig>::verify::<
            RescueTranscript<<PallasConfig as Pairing>::BaseField>,
        >(&merge_ipa_vk, &all_pi, &merge_ipa_proof, None)
        .unwrap();
        ark_std::println!("Proof verified");
        let st = SubTrees {
            commitment_subtree: all_pi[all_pi.len() - 2],
            nullifier_subtree: all_pi[all_pi.len() - 1],
        };
        let instance = AccInstance {
            comm: SWPoint(
                all_pi[all_pi.len() - 6],
                all_pi[all_pi.len() - 5],
                all_pi[all_pi.len() - 6] == Fq::zero(),
            ),
            eval: field_switching(&all_pi[all_pi.len() - 4]),
            eval_point: field_switching(&all_pi[all_pi.len() - 3]),
        };
        StoredProof::<PallasConfig, VestaConfig> {
            proof: merge_ipa_proof,
            pub_inputs: (
                global_public_inputs,
                st,
                instance,
                vec![passthrough_instance_1, passthrough_instance_2],
            ),
            vk: merge_ipa_vk,
            commit_key: stored_bounce.commit_key.clone(),
            g_poly,
            pi_stars: (
                [
                    stored_bounce.pi_stars.0[0].clone(),
                    stored_bounce_2.pi_stars.0[0].clone(),
                ]
                .to_vec(),
                pi_star_out,
            ), // TODO do we need 3 here?
        }
    }
    */
}
