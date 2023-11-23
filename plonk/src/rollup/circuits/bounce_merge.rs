use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::{
    accumulation::{
        accumulation_structs::PCSInstance, circuit::gadgets::verify_accumulation_gadget_sw,
        prover::AccProver,
    },
    circuit::plonk_partial_verifier::{PlonkIpaSWProofVar, SWVerifyingKeyVar},
    ipa_structs::{CommitKey, Proof, VerifyingKey},
    UnivariateIpaPCS,
};
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::{
        ecc::{short_weierstrass::SWPoint, SWToTEConParam},
        EmulatedVariable, EmulationConfig,
    },
    Circuit, PlonkCircuit,
};
use jf_utils::field_switching;

use super::structs::{AccInstance, GlobalPublicInputs, SubTrees};

// C1 is Pallas, C2 is Vesta
//

pub fn bounce_circuit<C1, C2>(
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::BaseField>,
    subtrees: SubTrees<C2::BaseField>,
    proof: Proof<C1>,
    g_poly: DensePolynomial<C1::ScalarField>,
    // Pass through, we dont do anything with this here
    passthrough_merge_acc: AccInstance<C2>,
    commit_key: CommitKey<C1>,
    // This is the acc calculated in bounce
    bounce_accs: [AccInstance<C1>; 2],
    bounce_pi_stars: [DensePolynomial<C1::ScalarField>; 2],
) -> Result<(PlonkCircuit<C2::ScalarField>, Vec<C1::ScalarField>), CircuitError>
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
    <C1 as Pairing>::ScalarField: EmulationConfig<<C1 as Pairing>::BaseField>,
{
    // This is useful to store re-stitched emulated variables into Field elements
    let mut public_outputs: Vec<C1::ScalarField> = vec![];
    let mut circuit = PlonkCircuit::<C2::ScalarField>::new_ultra_plonk(8);
    // This stores instances for the accumulator
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &vk)?;
    let g_gen: SWPoint<C1::BaseField> = vk.open_key.g_bases[0].into();

    // =======================================================
    // Public inputs for merge PV
    // first: global state
    let merge_public_inputs: Vec<C2::BaseField> = global_state.to_vec();
    let mut merge_public_inputs_vars = global_state
        .to_vec()
        .into_iter()
        .map(|x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    public_outputs.extend(global_state.to_vec());
    // then both bounce_accs
    let bounce_acc_vars = bounce_accs
        .clone()
        .into_iter()
        .flat_map(|x: AccInstance<_>| {
            x.to_vec_switch::<C2::BaseField>()
                .iter()
                .map(|&y| circuit.create_emulated_variable(y))
                .collect::<Result<Vec<_>, _>>()
        })
        .flatten()
        .collect::<Vec<_>>();

    // finally, the calculated subtrees
    let subtree_public_inputs_vars = subtrees
        .to_vec()
        .into_iter()
        .map(|x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    public_outputs.extend(subtrees.to_vec());

    // then the PV + acc result of the merge circuit
    let passthrough_public_inputs_vars = passthrough_merge_acc
        .to_vec()
        .iter()
        .map(|&x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    public_outputs.extend(passthrough_merge_acc.to_vec());

    merge_public_inputs_vars.extend(bounce_acc_vars.clone());
    merge_public_inputs_vars.extend(passthrough_public_inputs_vars);
    merge_public_inputs_vars.extend(subtree_public_inputs_vars);

    ark_std::println!("merge PI len: {}", merge_public_inputs.len()); // expect 22

    // for pub_input in public_input_var.iter() {
    //     let emul_wit = circuit.emulated_witness(pub_input)?;
    //     public_outputs.push(emul_wit);
    // }
    let proof_var = PlonkIpaSWProofVar::create_variables(&mut circuit, &proof)?;

    let (g_comm_var, u_var) = &verifying_key_var.partial_verify_circuit_ipa(
        &mut circuit,
        &g_gen,
        &merge_public_inputs_vars,
        &proof_var,
    )?;

    // This is to make g_comm_var a public input to the circuit
    // let is_infinity = circuit.is_neutral_sw_point::<C1>(g_comm_var)?;
    // circuit.enforce_false(is_infinity.into())?;
    // circuit.set_variable_public(g_comm_var.get_x())?;
    // circuit.set_variable_public(g_comm_var.get_y())?;
    // let bewl = circuit.create_public_boolean_variable(false)?;
    // circuit.create_public_variable(C2::ScalarField::zero())?;
    // // This is to make "point" of the instance public
    // for i in 0..u_var.native_vars().len() {
    //     circuit.set_variable_public(u_var.native_vars()[i])?;
    // }

    let pv_instance = PCSInstance::<UnivariateIpaPCS<C1>>::new(
        Commitment(circuit.sw_point_witness(g_comm_var)?.into()),
        C2::BaseField::from(0u64),
        circuit.emulated_witness(&u_var.clone())?,
    );

    // NB being lazy here, easy to debug
    let mut instances = vec![pv_instance];
    instances.push(bounce_accs[0].clone().into());
    instances.push(bounce_accs[1].clone().into());

    let mut g_polys = vec![g_poly];
    g_polys.push(bounce_pi_stars[0].clone());
    g_polys.push(bounce_pi_stars[1].clone());
    // Partial prove accumulation of all instances
    let prover = AccProver::new();

    let (acc, _) = prover
        .prove_accumulation(&commit_key, &instances, &g_polys)
        .unwrap();

    // TODO 23.11 create vars above and re-use for PV
    let mut g_comms_vars = vec![*g_comm_var];
    let g_comm_bounce = circuit.create_sw_point_variable(bounce_accs[0].comm)?;
    let g_comm_bounce_2 = circuit.create_sw_point_variable(bounce_accs[1].comm)?;
    let mut emul_g_comm_bounce: Vec<EmulatedVariable<_>> = vec![];
    emul_g_comm_bounce.extend(bounce_acc_vars[0..=2].to_vec());
    emul_g_comm_bounce.extend(bounce_acc_vars[5..=7].to_vec());

    let _ = vec![
        g_comm_bounce.get_x(),
        g_comm_bounce.get_y(),
        g_comm_bounce.get_inf().into(),
        g_comm_bounce_2.get_x(),
        g_comm_bounce_2.get_y(),
        g_comm_bounce_2.get_inf().into(),
    ]
    .iter()
    .zip(emul_g_comm_bounce)
    .map(|(x, y)| {
        let res = circuit.recombine_limbs(&y.native_vars(), <C1 as Pairing>::ScalarField::B)?;
        circuit.enforce_equal(*x, res)
    });

    g_comms_vars.push(g_comm_bounce);
    g_comms_vars.push(g_comm_bounce_2);

    let mut eval_vars = vec![circuit.create_emulated_variable(C1::ScalarField::zero())?];
    eval_vars.push(bounce_acc_vars[3].clone());
    eval_vars.push(bounce_acc_vars[8].clone());

    let mut eval_point_vars = vec![u_var.clone()];
    eval_point_vars.push(bounce_acc_vars[4].clone());
    eval_point_vars.push(bounce_acc_vars[9].clone());
    // 1 SW Point + 2 Field element made public here
    verify_accumulation_gadget_sw::<C1, C2, _, _, <<C1 as Pairing>::G1 as CurveGroup>::Config>(
        &mut circuit,
        &g_comms_vars,
        &eval_vars,
        &eval_point_vars,
        &acc,
    )?;
    // Acc.comm.0
    public_outputs.push(field_switching(&acc.instance.comm.0.x));
    public_outputs.push(field_switching(&acc.instance.comm.0.y));
    public_outputs.push(acc.instance.comm.0.infinity.into());
    public_outputs.push(acc.instance.value);
    public_outputs.push(acc.instance.point);

    Ok((circuit, public_outputs))
}

#[cfg(test)]
pub mod bounce_test {

    use crate::rollup::circuits::{
        bounce::bounce_test::bounce_test_helper,
        bounce_merge::bounce_circuit,
        merge::merge_test::merge_test_helper,
        structs::{AccInstance, GlobalPublicInputs, SubTrees},
        utils::{deserial_from_file, serial_to_file, StoredProof},
    };
    use ark_ec::pairing::Pairing;
    use ark_ff::One;
    use ark_poly::univariate::DensePolynomial;
    use curves::{
        pallas::PallasConfig,
        vesta::{Fq, Fr, VestaConfig},
    };
    use jf_plonk::{
        nightfall::{
            ipa_structs::{CommitKey, Proof, VerifyingKey},
            PlonkIpaSnark,
        },
        proof_system::UniversalSNARK,
        transcript::RescueTranscript,
    };
    use jf_relation::{
        gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit, PlonkCircuit,
    };
    use jf_utils::{field_switching, test_rng};

    #[test]
    pub fn bounce_merge_test() {
        let stored_bounce = bounce_test_helper();
        let stored_proof_merge = merge_test_helper(stored_bounce, Default::default());
        bounce_merge_test_helper(stored_proof_merge);
    }
    pub fn bounce_merge_test_helper(
        stored_proof_merge: StoredProof<PallasConfig, VestaConfig>,
    ) -> (PlonkCircuit<Fr>, StoredProof<VestaConfig, PallasConfig>) {
        let mut rng = test_rng();
        let (global_public_inputs, subtree_public_inputs, passthrough_instance, bounce_accs) =
            stored_proof_merge.pub_inputs;

        let (mut bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
            stored_proof_merge.vk,
            global_public_inputs.clone(),
            subtree_public_inputs.clone(),
            stored_proof_merge.proof,
            stored_proof_merge.g_poly,
            passthrough_instance,
            stored_proof_merge.commit_key.0.clone(),
            [bounce_accs[0].clone(), bounce_accs[1].clone()],
            [
                stored_proof_merge.pi_stars.0[0].clone(),
                stored_proof_merge.pi_stars.0[1].clone(),
            ],
        )
        .unwrap();
        bounce_circuit
            .check_circuit_satisfiability(&bounce_circuit.public_input().unwrap())
            .unwrap();
        bounce_circuit.finalize_for_arithmetization().unwrap();
        let bounce_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            bounce_circuit.srs_size().unwrap(),
            &mut rng,
        ).unwrap();
        let (bounce_ipa_pk, bounce_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&bounce_ipa_srs, &bounce_circuit).unwrap();
        let now = std::time::Instant::now();
        let (bounce_ipa_proof, g_poly, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &bounce_circuit, &bounce_ipa_pk, None)
            .unwrap();
        ark_std::println!("Proving time: {}", now.elapsed().as_secs());
        PlonkIpaSnark::<VestaConfig>::verify::<
            RescueTranscript<<VestaConfig as Pairing>::BaseField>,
        >(
            &bounce_ipa_vk,
            &bounce_circuit.public_input().unwrap(),
            &bounce_ipa_proof,
            None,
        )
        .unwrap();

        ark_std::println!("Bounce proof verified");

        // public output is in Pallas::scalar

        // This is the Vesta acc calculated in base
        let passthrough = AccInstance {
            comm: SWPoint(
                public_outputs[7],
                public_outputs[8],
                public_outputs[9] == Fq::one(),
            ),
            // These are originally Vesta Fr => small => safe conversion
            eval: field_switching(&public_outputs[10]),
            eval_point: field_switching(&public_outputs[11]),
        };

        // This is the Pallas acc we just made by Pv'ing base
        let instance = AccInstance {
            // This is originally a Pallas point => safe conversion
            comm: SWPoint(
                field_switching(&public_outputs[public_outputs.len() - 5]),
                field_switching(&public_outputs[public_outputs.len() - 4]),
                public_outputs[public_outputs.len() - 3] == Fq::one(),
            ),
            eval: public_outputs[public_outputs.len() - 2], // = 0 because we only PV one base
            eval_point: public_outputs[public_outputs.len() - 1],
        };

        let sp = StoredProof::<VestaConfig, PallasConfig> {
            proof: bounce_ipa_proof,
            pub_inputs: (
                global_public_inputs,
                subtree_public_inputs,
                instance,
                vec![passthrough],
            ),
            vk: bounce_ipa_vk,
            commit_key: stored_proof_merge.commit_key,
            g_poly,
            pi_stars: stored_proof_merge.pi_stars,
        };

        for i in 0..public_outputs.len() {
            ark_std::println!("Public Outputs {}: {}", i, public_outputs[i]);
        }

        // let file = std::fs::File::create("bounce_proof.json").unwrap();
        // serde_json::to_writer(file, &sp).unwrap();

        ark_std::println!(
            "Bounce merge PI length: {}",
            bounce_circuit.public_input().unwrap().len()
        );
        (bounce_circuit, sp)
    }
}
