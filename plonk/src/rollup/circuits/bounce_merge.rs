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
    circuit::plonk_partial_verifier::{PlonkIpaSWProofVar, SWVerifyingKeyVar},
    ipa_structs::{CommitKey, Proof, VerifyingKey},
    UnivariateIpaPCS,
};
use jf_primitives::{pcs::prelude::Commitment, rescue::RescueParameter};
use jf_relation::{
    errors::CircuitError,
    gadgets::{
        ecc::{short_weierstrass::SWPoint, SWToTEConParam},
        EmulationConfig,
    },
    Circuit, PlonkCircuit,
};
use jf_utils::field_switching;

use super::structs::{AccInstance, GlobalPublicInputs};

// C1 is Pallas, C2 is Vesta
//

pub fn bounce_circuit<C1, C2>(
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::BaseField>,
    proof: Proof<C1>,
    // Pass through, we dont do anything with this here
    base_acc: AccInstance<C2::BaseField>,
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
    let mut instances = vec![];
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &vk)?;
    let g_gen: SWPoint<C1::BaseField> = vk.open_key.g_bases[0].into();
    let base_public_inputs = vec![
        commitment_root,
        vk_root,
        initial_nullifier_root,
        initial_leaf_count,
        new_nullifier_root,
        commitment_subtree,
        nullifier_subtree,
        passthrough_pv_acc.comm.0.x,
        passthrough_pv_acc.comm.0.y,
        (passthrough_pv_acc.comm.0.infinity).into(),
        field_switching(&passthrough_pv_acc.value),
        field_switching(&passthrough_pv_acc.point),
    ];

    // let mut merge_accs_pi = vec![];

    let public_input_var = base_public_inputs
        .into_iter()
        .map(|x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    for i in 0..public_input_var.len() {
        let emul_wit = circuit.emulated_witness(&public_input_var[i])?;
        public_outputs.push(emul_wit);
    }
    let proof_var = PlonkIpaSWProofVar::create_variables(&mut circuit, &proof)?;

    let (g_comm_var, u_var) = &verifying_key_var.partial_verify_circuit_ipa(
        &mut circuit,
        &g_gen,
        &public_input_var,
        &proof_var,
    )?;
    let instance = PCSInstance::<UnivariateIpaPCS<C1>>::new(
        Commitment(circuit.sw_point_witness(g_comm_var)?.into()),
        C1::ScalarField::from(0u64),
        circuit.emulated_witness(u_var)?,
    );
    instances.push(instance);

    // This is to make g_comm_var a public input to the circuit
    let is_infinity = circuit.is_neutral_sw_point::<C1>(g_comm_var)?;
    circuit.enforce_false(is_infinity.into())?;
    circuit.set_variable_public(g_comm_var.get_x())?;
    circuit.set_variable_public(g_comm_var.get_y())?;
    let bewl = circuit.create_public_boolean_variable(false)?;
    // This is to make "value" of the instance public
    // let public_eval = circuit.create_public_variable(C1::BaseField::from(0u64))?;
    // This is to make "point" of the instance public
    for i in 0..u_var.native_vars().len() {
        circuit.set_variable_public(u_var.native_vars()[i])?;
    }

    // We push it onto public_outputs array so it's easier to work with outside
    // the circuit
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_x())?));
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_y())?));
    public_outputs.push(field_switching(&circuit.witness(bewl.into())?));
    // public_outputs.push(field_switching(&circuit.witness(public_eval)?));
    public_outputs.push(circuit.emulated_witness(u_var)?);

    // if commit_key.is_some() {
    //     let prover = AccProver::new();
    //     instances.extend(merge_accs.unwrap().iter().cloned());
    //     let mut g_polys = vec![g_poly];
    //     g_polys.extend(merge_pi_stars.unwrap().iter().cloned());
    //     // 1 SW Point + 2 Field element made public here
    //     let (acc, _) = prover
    //         .prove_accumulation(&commit_key.unwrap(), &instances, &g_polys)
    //         .unwrap();
    //
    //     verify_accumulation_gadget_sw_native::<
    //         C1,
    //         C2,
    //         _,
    //         _,
    //         <<C1 as Pairing>::G1 as CurveGroup>::Config,
    //     >(
    //         &mut circuit,
    //         &[g_comm_var],
    //         &[0; 2],
    //         &u_challenges_vars.as_slice(),
    //         &acc,
    //     )?;
    // }
    //
    Ok((circuit, public_outputs))
}

#[cfg(test)]
pub mod bounce_test {

    use crate::rollup::circuits::{
        base::base_test::test_base_rollup_helper_transfer,
        bounce::bounce_circuit,
        utils::{deserial_from_file, serial_to_file},
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
            accumulation::accumulation_structs::PCSInstance,
            ipa_structs::{CommitKey, Proof, VerifyingKey},
            PlonkIpaSnark, UnivariateIpaPCS,
        },
        proof_system::UniversalSNARK,
        transcript::RescueTranscript,
    };
    use jf_primitives::pcs::prelude::Commitment;
    use jf_relation::{
        gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit, PlonkCircuit,
    };
    use jf_utils::{field_switching, test_rng};

    #[test]
    fn bounce_test() {
        bounce_test_helper();
    }
    pub fn bounce_test_helper() -> (
        Vec<Fq>,
        Proof<VestaConfig>,
        VerifyingKey<VestaConfig>,
        DensePolynomial<Fr>,
        CommitKey<VestaConfig>,
        DensePolynomial<Fr>,
    ) {
        let (circuit, proof, base_vk, (v_ck, p_ck), pi_star) = test_base_rollup_helper_transfer();

        // let stored_base = deserial_from_file("base_circuit_output.json");

        let mut rng = test_rng();
        let pub_inputs = circuit.public_input().unwrap();
        // let base_vk = stored_base.vk;
        // let proof = stored_base.proof;
        // let pi_star = stored_base.pi_star;

        let instance_sw = SWPoint(pub_inputs[7], pub_inputs[8], pub_inputs[9] == Fq::one());
        let instance_value = pub_inputs[10];
        let instance_point = pub_inputs[11];
        let instance = PCSInstance::<UnivariateIpaPCS<VestaConfig>>::new(
            Commitment(instance_sw.into()),
            field_switching(&instance_value),
            field_switching(&instance_point),
        );
        let (mut bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
            base_vk,
            pub_inputs[0],
            pub_inputs[1],
            pub_inputs[2],
            pub_inputs[3],
            pub_inputs[4],
            pub_inputs[5],
            pub_inputs[6],
            proof,
            instance,
            None,
            None,
            None,
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

        // serial_to_file(
        //     bounce_ipa_proof.clone(),
        //     public_outputs.clone(),
        //     bounce_ipa_vk.clone(),
        //     v_ck.clone(),
        //     pi_star.clone(),
        //     "bounce_proof",
        // );
        //
        for i in 0..bounce_circuit.public_input().unwrap().len() {
            ark_std::println!(
                "bounce public input {}: {}",
                i,
                bounce_circuit.public_input().unwrap()[i]
            );
        }
        ark_std::println!("Proof verified");
        (
            public_outputs,
            bounce_ipa_proof,
            bounce_ipa_vk,
            g_poly,
            v_ck,
            pi_star,
        )
    }
}
