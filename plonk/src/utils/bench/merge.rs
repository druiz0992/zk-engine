/*
use super::bounce::bounce_circuit_helper_generator;
use crate::rollup::circuits::{
    merge::merge_circuit,
    structs::{AccInstance, SubTrees},
    utils::StoredProof,
};
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

pub fn merge_circuit_helper_generator<
    const I: usize,
    const N: usize,
    const C: usize,
    const D: usize,
>() -> StoredProof<PallasConfig, VestaConfig> {
    // Below taken from merge_test_helper
    let mut rng = test_rng();
    let stored_bounce = bounce_circuit_helper_generator::<I, C, N, D>();
    let stored_bounce_2 = stored_bounce.clone();
    let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
        stored_bounce.pub_inputs;
    let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;
    ark_std::println!("Creating Merge Circuit");
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
    merge_circuit.finalize_for_arithmetization().unwrap();
    let merge_ipa_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            merge_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();
    let (merge_ipa_pk, merge_ipa_vk) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&merge_ipa_srs, &merge_circuit).unwrap();

    let (merge_ipa_proof, g_poly, _) = PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<PallasConfig as Pairing>::BaseField>,
    >(&mut rng, &merge_circuit, &merge_ipa_pk, None)
    .unwrap();

    ark_std::println!("Created Merge Proof");

    let all_pi = merge_circuit.public_input().unwrap();
    let st = SubTrees {
        commitment_subtree: all_pi[all_pi.len() - 2],
        nullifier_subtree: all_pi[all_pi.len() - 1],
    };
    let instance = AccInstance {
        comm: SWPoint(
            all_pi[all_pi.len() - 6],
            all_pi[all_pi.len() - 5],
            all_pi[all_pi.len() - 6] == Fr::zero(),
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
