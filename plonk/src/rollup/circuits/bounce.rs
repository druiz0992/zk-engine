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

use super::structs::{AccInstance, GlobalPublicInputs, SubTrees};

// C1 is Pallas, C2 is Vesta
//

pub fn bounce_circuit<C1, C2>(
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::BaseField>,
    subtrees: SubTrees<C2::BaseField>,
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
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &vk)?;
    let g_gen: SWPoint<C1::BaseField> = vk.open_key.g_bases[0].into();

    let mut base_public_inputs: Vec<C2::BaseField> = global_state.to_vec();

    let subtree_public_inputs = subtrees.to_vec();
    base_public_inputs.extend(subtree_public_inputs);

    let passthrough_public_inputs = base_acc.to_vec();
    base_public_inputs.extend(passthrough_public_inputs);

    let public_input_var = base_public_inputs
        .into_iter()
        .map(|x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

    for pub_input in public_input_var.iter() {
        let emul_wit = circuit.emulated_witness(pub_input)?;
        public_outputs.push(emul_wit);
    }
    let proof_var = PlonkIpaSWProofVar::create_variables(&mut circuit, &proof)?;

    let (g_comm_var, u_var) = &verifying_key_var.partial_verify_circuit_ipa(
        &mut circuit,
        &g_gen,
        &public_input_var,
        &proof_var,
    )?;

    // This is to make g_comm_var a public input to the circuit
    let is_infinity = circuit.is_neutral_sw_point::<C1>(g_comm_var)?;
    circuit.enforce_false(is_infinity.into())?;
    circuit.set_variable_public(g_comm_var.get_x())?;
    circuit.set_variable_public(g_comm_var.get_y())?;
    let bewl = circuit.create_public_boolean_variable(false)?;
    circuit.create_public_variable(C2::ScalarField::zero())?;
    // This is to make "point" of the instance public
    for i in 0..u_var.native_vars().len() {
        circuit.set_variable_public(u_var.native_vars()[i])?;
    }

    // We push it onto public_outputs array so it's easier to work with outside
    // the circuit
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_x())?));
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_y())?));
    public_outputs.push(field_switching(&circuit.witness(bewl.into())?));
    public_outputs.push(C2::BaseField::zero());
    public_outputs.push(circuit.emulated_witness(u_var)?);

    Ok((circuit, public_outputs))
}

#[cfg(test)]
pub mod bounce_test {

    use crate::rollup::circuits::{
        base::base_test::test_base_rollup_helper_transfer,
        bounce::bounce_circuit,
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
    use jf_utils::test_rng;

    #[test]
    fn bounce_test() {
        bounce_test_helper();
    }
    pub fn bounce_test_helper() -> (PlonkCircuit<Fr>, StoredProof<VestaConfig>) {
        let stored_proof_base = test_base_rollup_helper_transfer();

        let mut rng = test_rng();
        let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
            stored_proof_base.pub_inputs;

        let (mut bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
            stored_proof_base.vk,
            global_public_inputs.clone(),
            subtree_public_inputs.clone(),
            stored_proof_base.proof,
            passthrough_instance.switch_field(),
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

        ark_std::println!("Proof verified");
        let instance = AccInstance {
            comm: SWPoint(
                public_outputs[7],
                public_outputs[8],
                public_outputs[9] == Fq::one(),
            ),
            eval: public_outputs[10],
            eval_point: public_outputs[11],
        };
        // let switched_field_instance = passthrough_instance.switch_field();
        let passthrough = AccInstance {
            comm: SWPoint(
                public_outputs[public_outputs.len() - 5],
                public_outputs[public_outputs.len() - 4],
                public_outputs[public_outputs.len() - 3] == Fq::one(),
            ),
            eval: public_outputs[public_outputs.len() - 2],
            eval_point: public_outputs[public_outputs.len() - 1],
        };
        ark_std::println!("Length of publicoutputs: {}", public_outputs.len());
        // ark_std::println!("Switch_field_point: {}", switched_field_instance.comm.0);
        // ark_std::println!("passthrough _point: {}", passthrough_instance.comm.0);
        // ark_std::println!("Switch_field_eval: {}", switched_field_instance.eval);
        // ark_std::println!("passthrough_eval: {}", passthrough_instance.eval);
        let sp = StoredProof {
            proof: bounce_ipa_proof,
            pub_inputs: (
                global_public_inputs,
                subtree_public_inputs,
                instance,
                vec![passthrough], // Things that are no longer passthroughs
            ),
            vk: bounce_ipa_vk,
            commit_key: stored_proof_base.commit_key,
            g_poly,
            pi_stars: stored_proof_base.pi_stars,
        };

        // let file = std::fs::File::create("bounce_proof.json").unwrap();
        // serde_json::to_writer(file, &sp).unwrap();

        ark_std::println!(
            "PI length: {}",
            bounce_circuit.public_input().unwrap().len()
        );
        (bounce_circuit, sp)
    }
}
