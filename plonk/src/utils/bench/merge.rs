use super::base::TransactionType;
use super::bounce::bounce_circuit_helper_generator;
use crate::rollup::circuits::{
    merge::merge_circuit,
    structs::{AccInstance, SubTrees},
    utils::StoredProof,
};
use crate::utils::bench;
use ark_ff::Zero;
use curves::{
    pallas::{Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_relation::{gadgets::ecc::short_weierstrass::SWPoint, Circuit};
use jf_utils::field_switching;

pub fn merge_circuit_helper_generator<const D: usize>(
    transaction_sequence: &[TransactionType],
) -> StoredProof<PallasConfig, VestaConfig> {
    // Below taken from merge_test_helper
    let stored_bounce = bounce_circuit_helper_generator::<D>(transaction_sequence);
    let stored_bounce_2 = stored_bounce.clone();
    let (global_public_inputs, subtree_pi_1, passthrough_instance_1, instance_1) =
        stored_bounce.pub_inputs;
    let (_, subtree_pi_2, passthrough_instance_2, instance_2) = stored_bounce_2.pub_inputs;
    ark_std::println!("Creating Merge Circuit");
    let (merge_circuit, pi_star_out) = merge_circuit::<VestaConfig, PallasConfig>(
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

    let merge_artifacts =
        bench::generate_rollup_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _, _>(
            &merge_circuit,
            true,
        )
        .unwrap();

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
        proof: merge_artifacts.proof,
        pub_inputs: (
            global_public_inputs,
            st,
            instance,
            vec![passthrough_instance_1, passthrough_instance_2],
        ),
        vk: merge_artifacts.vk,
        commit_key: stored_bounce.commit_key.clone(),
        g_poly: merge_artifacts.g_poly,
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
