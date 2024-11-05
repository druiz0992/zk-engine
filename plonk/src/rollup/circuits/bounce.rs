use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::{
    circuit::plonk_partial_verifier::{PlonkIpaSWProofVar, SWVerifyingKeyVar},
    ipa_structs::{Proof, VerifyingKey},
};
use jf_primitives::rescue::RescueParameter;
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

#[allow(clippy::type_complexity)]
pub fn bounce_circuit<C1, C2>(
    vk: VerifyingKey<C1>,
    // Std Global State
    global_state: GlobalPublicInputs<C2::BaseField>,
    subtrees: SubTrees<C2::BaseField>,
    proof: Proof<C1>,
    // Pass through, we dont do anything with this here
    base_acc: AccInstance<C2>,
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
    let mut circuit = PlonkCircuit::<C2::ScalarField>::new_ultra_plonk(8);
    let verifying_key_var = SWVerifyingKeyVar::new_from_ipa(&mut circuit, &vk)?;
    let g_gen: SWPoint<C1::BaseField> = vk.open_key.g_bases[0].into();

    // Initialise public inputs for the circuit
    let mut base_public_inputs: Vec<C2::BaseField> = global_state.to_vec();

    let subtree_public_inputs = subtrees.to_vec();
    base_public_inputs.extend(subtree_public_inputs);

    let passthrough_public_inputs = base_acc.to_vec();
    base_public_inputs.extend(passthrough_public_inputs);

    // Convert public inputs to variables
    let public_input_var = base_public_inputs
        .iter()
        .map(|&x| circuit.create_public_emulated_variable(x))
        .collect::<Result<Vec<_>, _>>()?;

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
    // Set g_comm_var to public
    circuit.set_variable_public(g_comm_var.get_x())?;
    circuit.set_variable_public(g_comm_var.get_y())?;
    // circuit.set_variable_public(g_comm_var.get_inf().into())?;
    // Set evaluation to zero and public
    circuit.create_public_emulated_variable(C1::ScalarField::zero())?;
    // This is to make "point" of the instance public
    for u_var_limb in u_var.native_vars() {
        circuit.set_variable_public(u_var_limb)?;
    }

    // We push it onto public_outputs array so it's easier to work with outside
    // the circuit
    let mut public_outputs = base_public_inputs;
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_x())?));
    public_outputs.push(field_switching(&circuit.witness(g_comm_var.get_y())?));
    // public_outputs.push(field_switching(
    //     &circuit.witness(g_comm_var.get_inf().into())?,
    // ));
    public_outputs.push(C2::BaseField::zero());
    public_outputs.push(circuit.emulated_witness(u_var)?);

    Ok((circuit, public_outputs))
}

#[cfg(test)]
pub mod bounce_test {

    use crate::rollup::circuits::{
        base::base_test::test_base_rollup_helper_transfer, bounce::bounce_circuit,
        structs::AccInstance, utils::StoredProof,
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
    fn bounce_test() {
        bounce_test_helper();
    }
    pub fn bounce_test_helper() -> StoredProof<VestaConfig, PallasConfig> {
        const I: usize = 2;
        const C: usize = 1;
        const N: usize = 2;
        const D: usize = 8;
        let stored_proof_base = test_base_rollup_helper_transfer::<I, C, N, D>();

        let mut rng = test_rng();
        let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
            stored_proof_base.pub_inputs;

        let (mut bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
            stored_proof_base.vk,
            global_public_inputs.clone(),
            subtree_public_inputs.clone(),
            stored_proof_base.proof,
            passthrough_instance,
        )
        .unwrap();
        ark_std::println!("Bounce constraints: {}", bounce_circuit.num_gates());
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
                public_outputs[7] == Fq::zero(),
            ),
            // These are originally Vesta Fr => small => safe conversion
            eval: field_switching(&public_outputs[9]),
            eval_point: field_switching(&public_outputs[10]),
        };

        // This is the Pallas acc we just made by Pv'ing base
        let instance = AccInstance {
            // This is originally a Pallas point => safe conversion
            comm: SWPoint(
                field_switching(&public_outputs[public_outputs.len() - 4]),
                field_switching(&public_outputs[public_outputs.len() - 3]),
                public_outputs[public_outputs.len() - 4] == Fq::zero(),
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
            commit_key: stored_proof_base.commit_key,
            g_poly,
            pi_stars: (
                [stored_proof_base.g_poly].to_vec(),
                stored_proof_base.pi_stars.1,
            ),
        };

        sp
    }
}
