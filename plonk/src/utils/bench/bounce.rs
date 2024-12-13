use super::base;
use crate::client::ClientPlonkCircuit;
use crate::rollup::circuits::{bounce::bounce_circuit, structs::AccInstance, utils::StoredProof};
use crate::utils::bench;
use ark_ff::Zero;
use curves::{
    pallas::{Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_relation::gadgets::ecc::short_weierstrass::SWPoint;
use jf_utils::field_switching;

pub fn bounce_circuit_helper_generator<const D: usize>(
    client_circuits: &[Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>],
) -> StoredProof<VestaConfig, PallasConfig> {
    // Below taken from bounce_test_helper
    ark_std::println!("Creating Bounce Circuit");
    let stored_proof_base = base::base_circuit_helper_generator::<D>(client_circuits, 1);
    let (global_public_inputs, subtree_public_inputs, passthrough_instance, _) =
        stored_proof_base.pub_inputs;
    let (bounce_circuit, public_outputs) = bounce_circuit::<PallasConfig, VestaConfig>(
        stored_proof_base.vk,
        global_public_inputs.clone(),
        subtree_public_inputs.clone(),
        stored_proof_base.proof,
        passthrough_instance,
    )
    .unwrap();

    let bounce_artifacts =
        bench::generate_rollup_circuit_artifacts_and_verify::<VestaConfig, PallasConfig, _, _>(
            &bounce_circuit,
            true,
        )
        .unwrap();

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
        proof: bounce_artifacts.proof,
        pub_inputs: (
            global_public_inputs,
            subtree_public_inputs,
            instance,
            vec![passthrough],
        ),
        vk: bounce_artifacts.vk,
        commit_key: stored_proof_base.commit_key,
        g_poly: bounce_artifacts.g_poly,
        pi_stars: (
            [stored_proof_base.g_poly].to_vec(),
            stored_proof_base.pi_stars.1,
        ),
    }
}
