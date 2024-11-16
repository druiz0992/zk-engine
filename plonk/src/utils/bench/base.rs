use super::tree::tree_generator_from_client_inputs;
use crate::client::circuits::transfer;
use crate::client::PlonkCircuitParams;
use crate::rollup::circuits::client_input::LowNullifierInfo;
use crate::rollup::circuits::{
    base::base_rollup_circuit,
    client_input::ClientInput,
    structs::{AccInstance, GlobalPublicInputs, SubTrees},
    utils::StoredProof,
};
use ark_ec::pairing::Pairing;
use ark_ff::Zero;
use ark_std::UniformRand;
use curves::{
    pallas::{Fq, Fr, PallasConfig},
    vesta::VestaConfig,
};
use jf_plonk::{
    nightfall::PlonkIpaSnark, proof_system::UniversalSNARK, transcript::RescueTranscript,
};
use jf_primitives::pcs::StructuredReferenceString;
use jf_relation::{gadgets::ecc::short_weierstrass::SWPoint, Arithmetization, Circuit};
use jf_utils::field_switching;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::{
    membership_tree::MembershipTree, non_membership_tree::IndexedMerkleTree, tree::AppendTree,
};
/*
pub fn base_circuit_helper_generator<
    const I: usize,
    const C: usize,
    const N: usize,
    const D: usize,
>() -> StoredProof<PallasConfig, VestaConfig> {
    // Below taken from test_base_rollup_helper_transfer
    let mut rng = ChaChaRng::from_entropy();
    let mut client_inputs = vec![];
    let mut global_comm_roots: Vec<Fr> = vec![];
    let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
    let init_nullifier_root = nullifier_tree.root();
    let mut g_polys = vec![];
    let mut transfer_ipa_srs = Default::default(); // avoid re-generating

    ark_std::println!("Creating {} Transfer Circuits", I);

    let token_id = Some(Fq::rand(&mut rng));
    for i in 0..I {
        let PlonkCircuitParams {
            circuit: transfer_circuit,
            public_inputs: transfer_inputs,
        } = transfer::utils::transfer_with_random_inputs::<PallasConfig, VestaConfig, _, C, N, D>(
            token_id,
        )
        .unwrap();
        if i == 0 {
            transfer_ipa_srs = <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
                    transfer_circuit.srs_size().unwrap(),
                    &mut rng,
                ).unwrap();
        }

        let (transfer_ipa_pk, transfer_ipa_vk) =
            PlonkIpaSnark::<VestaConfig>::preprocess(&transfer_ipa_srs, &transfer_circuit).unwrap();

        let (transfer_ipa_proof, g_poly, _) =
            PlonkIpaSnark::<VestaConfig>::prove_for_partial::<
                _,
                _,
                RescueTranscript<<VestaConfig as Pairing>::BaseField>,
            >(&mut rng, &transfer_circuit, &transfer_ipa_pk, None)
            .unwrap();
        g_polys.push(g_poly);

        let input_builder = ClientInputBuilder::<VestaConfig, C, N, D>::new();
        let mut client_input =
            ClientInput::<VestaConfig, C, N, D>::new(transfer_ipa_proof, transfer_ipa_vk.clone());

        let switched_root: <VestaConfig as Pairing>::BaseField =
            field_switching(&transfer_inputs.commitment_root[0]);
        let nullifiers = input_builder
            .to_nullifiers_array(transfer_inputs.nullifiers)
            .unwrap();
        let LowNullifierInfo {
            nullifiers: low_nullifier,
            indices: low_nullifier_indices,
            paths: low_nullifier_mem_path,
        } = input_builder.update_nullifier_tree(&mut nullifier_tree, nullifiers);

        client_input
            .set_nullifiers(nullifiers)
            .set_commitments(
                input_builder
                    .to_commitments_array(transfer_inputs.commitments)
                    .unwrap(),
            )
            .set_commitment_tree_root(
                input_builder
                    .to_commitments_tree_root_array(transfer_inputs.commitment_root)
                    .unwrap(),
            )
            .set_low_nullifier_info(low_nullifier, low_nullifier_indices, low_nullifier_mem_path)
            .set_eph_pub_key(
                input_builder
                    .to_eph_key_array(transfer_inputs.ephemeral_public_key)
                    .unwrap(),
            )
            .set_ciphertext(
                input_builder
                    .to_ciphertext_array(transfer_inputs.ciphertexts)
                    .unwrap(),
            );

        client_inputs.push(client_input);
        global_comm_roots.push(switched_root);
    }
    ark_std::println!("Created {} Transfer Proofs", I);
    // all have the same vk
    let vks = vec![client_inputs[0].vk.clone()];
    let comms: Vec<Fq> = vec![];

    let (vk_tree, _, _, global_comm_tree) = tree_generator(vks, comms, vec![], global_comm_roots);

    for (i, ci) in client_inputs.iter_mut().enumerate() {
        let global_root_path = global_comm_tree
            .membership_witness(i)
            .unwrap()
            .try_into()
            .unwrap();
        ci.path_comm_tree_root_to_global_tree_root = [global_root_path; N];
        ci.path_comm_tree_index = [Fr::from(i as u32); N];
        ci.vk_paths = vk_tree.membership_witness(0).unwrap().try_into().unwrap();
        // vk index is already (correctly) zero
    }

    let vesta_srs =
        <PlonkIpaSnark<VestaConfig> as UniversalSNARK<VestaConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
    let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(21)).unwrap();

    let pallas_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            2usize.pow(21),
            &mut rng,
        )
        .unwrap();
    let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(21)).unwrap();

    let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();

    ark_std::println!("Creating Base Circuit");

    let (mut base_circuit, pi_star) = base_rollup_circuit::<VestaConfig, PallasConfig, I, C, N, D>(
        client_inputs.try_into().unwrap(),
        vk_tree.root(),
        init_nullifier_root,
        initial_nullifier_tree.leaf_count().into(),
        global_comm_tree.root(),
        g_polys.try_into().unwrap(),
        vesta_commit_key.clone(),
    )
    .unwrap();
    base_circuit
        .check_circuit_satisfiability(&base_circuit.public_input().unwrap())
        .unwrap();
    base_circuit.finalize_for_arithmetization().unwrap();
    let base_ipa_srs =
        <PlonkIpaSnark<PallasConfig> as UniversalSNARK<PallasConfig>>::universal_setup_for_testing(
            base_circuit.srs_size().unwrap(),
            &mut rng,
        )
        .unwrap();

    let (base_ipa_pk, base_ipa_vk) =
        PlonkIpaSnark::<PallasConfig>::preprocess(&base_ipa_srs, &base_circuit).unwrap();

    let (base_ipa_proof, g_poly, _) = PlonkIpaSnark::<PallasConfig>::prove_for_partial::<
        _,
        _,
        RescueTranscript<<PallasConfig as Pairing>::BaseField>,
    >(&mut rng, &base_circuit, &base_ipa_pk, None)
    .unwrap();

    ark_std::println!("Created Base Proof");

    let public_inputs = base_circuit.public_input().unwrap();
    let global_public_inputs = GlobalPublicInputs::from_vec(public_inputs.clone());
    let subtree_pi = SubTrees::from_vec(public_inputs[5..=6].to_vec());
    let instance: AccInstance<VestaConfig> = AccInstance {
        comm: SWPoint(
            public_inputs[7],
            public_inputs[8],
            public_inputs[7] == Fr::zero(),
        ),
        // values are originally Vesta scalar => safe switch back into 'native'
        eval: field_switching(&public_inputs[9]),
        eval_point: field_switching(&public_inputs[10]),
    };

    StoredProof {
        proof: base_ipa_proof,
        pub_inputs: (global_public_inputs, subtree_pi, instance, vec![]),
        vk: base_ipa_vk,
        commit_key: (pallas_commit_key, vesta_commit_key),
        g_poly,
        pi_stars: (Default::default(), pi_star),
    }
}
    */
