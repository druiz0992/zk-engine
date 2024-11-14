use super::base::base_circuit_helper_generator;
use crate::rollup::circuits::{bounce::bounce_circuit, structs::AccInstance, utils::StoredProof};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use curves::{
    pallas::{Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_relation::{gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit};
use jf_utils::{field_switching, test_rng};

pub fn bounce_circuit_helper_generator<
    const I: usize,
    const N: usize,
    const C: usize,
    const D: usize,
>() -> StoredProof<VestaConfig, PallasConfig> {
    // Below taken from bounce_test_helper
    let mut rng = test_rng();
    ark_std::println!("Creating Bounce Circuit");
    let stored_proof_base = base_circuit_helper_generator::<I, C, N, D>();
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
    bounce_circuit
        .check_circuit_satisfiability(&bounce_circuit.public_input().unwrap())
        .unwrap();
    bounce_circuit.finalize_for_arithmetization().unwrap();
    let bounce_ipa_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            bounce_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    let (bounce_ipa_pk, bounce_ipa_vk) =
        PlonkIpaSnark::<VestaConfig>::preprocess(&bounce_ipa_srs, &bounce_circuit).unwrap();
    let (bounce_ipa_proof, g_poly, _) = PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<VestaConfig as Pairing>::BaseField>,
    >(&mut rng, &bounce_circuit, &bounce_ipa_pk, None)
    .unwrap();
    ark_std::println!("Created Bounce Proof");
    // This is the Vesta acc calculated in base
    let passthrough = AccInstance {
        comm: SWPoint(
            public_outputs[7],
            public_outputs[8],
            public_outputs[7] == Fr::zero(),
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
            public_outputs[public_outputs.len() - 4] == Fr::zero(),
        ),
        eval: public_outputs[public_outputs.len() - 2], // = 0 because we only PV one base
        eval_point: public_outputs[public_outputs.len() - 1],
    };

    StoredProof::<VestaConfig, PallasConfig> {
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
    }
}
