use super::generate_rollup_circuit_artifacts_and_verify;
use super::tree;
use crate::client::structs::ClientPubInput;
use crate::client::ClientPlonkCircuit;
use crate::primitives::circuits::kem_dem::KemDemParams;
use crate::rollup::circuits::base;
use crate::rollup::circuits::client_input;
use crate::rollup::circuits::client_input::ClientInput;
use crate::rollup::circuits::utils::StoredProof;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use common::crypto::poseidon::constants::PoseidonParams;
use curves::pallas::{Fq, Fr, PallasConfig};
use curves::vesta::VestaConfig;
use jf_plonk::nightfall::ipa_structs::{CommitKey, Proof, ProvingKey, VerifyingKey};
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::UniversalSNARK;
use jf_plonk::transcript::RescueTranscript;
use jf_primitives::pcs::StructuredReferenceString;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{gadgets::ecc::SWToTEConParam, Arithmetization, Circuit, PlonkCircuit};
use jf_utils::field_switching;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::{non_membership_tree::IndexedMerkleTree, AppendTree};
use zk_macros::client_bounds;

#[derive(Clone, Debug)]
pub enum TransactionType {
    Mint,
    Transfer,
}

pub fn base_circuit_helper_generator<const D: usize>(
    client_circuits: &[Box<dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>>],
) -> StoredProof<PallasConfig, VestaConfig> {
    let mut rng = ChaChaRng::from_entropy();
    let mut client_inputs: Vec<ClientInput<VestaConfig>> = vec![];
    let mut global_comm_roots: Vec<Fr> = vec![];
    let mut nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();
    let init_nullifier_root = nullifier_tree.root();
    let mut g_polys = vec![];
    let initial_nullifier_tree = IndexedMerkleTree::<Fr, 32>::new();

    let token_id = Some(Fq::rand(&mut rng));

    #[allow(clippy::needless_range_loop)]
    for i in 0..client_circuits.len() {
        build_client_inputs(
            &mut client_inputs,
            &mut nullifier_tree,
            &mut global_comm_roots,
            &mut g_polys,
            &*client_circuits[i],
            token_id,
        )
        .unwrap();
    }

    /* ----------------------------------------------------------------------------------
     * ---------------------------  Base Rollup Circuit ----------------------------------
     * ----------------------------------------------------------------------------------
     */

    let zk_trees =
        tree::tree_generator_from_client_inputs::<8>(&mut client_inputs, global_comm_roots)
            .unwrap();

    let (vesta_commit_key, pallas_commit_key) = build_commit_keys().unwrap();

    let (base_rollup_circuit, pi_star) = base::base_rollup_circuit::<VestaConfig, PallasConfig, 8>(
        client_inputs,
        zk_trees.vk_tree.root(),
        // initial_nullifier_tree.root,
        init_nullifier_root,
        initial_nullifier_tree.leaf_count().into(),
        zk_trees.global_root_tree.root(),
        g_polys,
        vesta_commit_key.clone(),
    )
    .unwrap();

    ark_std::println!(
        "Base rollup circuit constraints: {:?}",
        base_rollup_circuit.num_gates()
    );

    let base_artifacts =
        generate_rollup_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _, _>(
            &base_rollup_circuit,
            false,
        )
        .unwrap();

    StoredProof::new_from_base(
        &base_rollup_circuit,
        base_artifacts.proof,
        base_artifacts.vk,
        pallas_commit_key,
        vesta_commit_key,
        base_artifacts.g_poly,
        pi_star,
        vec![],
    )
    .unwrap()
}

pub struct ClientCircuitArtifacts<V>
where
    V: Pairing,
    <V::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub proof: Proof<V>,
    pub g_poly: DensePolynomial<V::ScalarField>,
    pub pk: ProvingKey<V>,
    pub vk: VerifyingKey<V>,
}

#[client_bounds]
fn generate_client_circuit_artifacts_and_verify<P, V, VSW>(
    circuit: &PlonkCircuit<V::ScalarField>,
    verify_flag: bool,
) -> Result<ClientCircuitArtifacts<V>, String> {
    let mut rng = ChaChaRng::from_entropy();
    let srs_size = circuit
        .srs_size()
        .map_err(|_| "Couldnt extract Client Circuit SRS Size".to_string())?;
    let ipa_srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)
            .map_err(|_| "Couldnt compute Client Circuit SRS")?;
    let (ipa_pk, ipa_vk) = PlonkIpaSnark::<V>::preprocess(&ipa_srs, circuit)
        .map_err(|_| "Couldn't compute Client Circuit PK/VK".to_string())?;

    let (ipa_proof, g_poly, _) =
        PlonkIpaSnark::<V>::prove_for_partial::<_, _, RescueTranscript<<V as Pairing>::BaseField>>(
            &mut rng, circuit, &ipa_pk, None,
        )
        .map_err(|_| "Couldn't compute Client Circuit Proof".to_string())?;
    if verify_flag {
        PlonkIpaSnark::<V>::verify::<RescueTranscript<<V as Pairing>::BaseField>>(
            &ipa_vk,
            &circuit.public_input().unwrap(),
            &ipa_proof,
            None,
        )
        .map_err(|_| "Couldn't verify Client Circuit Proof".to_string())?;
        ark_std::println!("Client proof verified");
    }
    Ok(ClientCircuitArtifacts {
        proof: ipa_proof,
        g_poly,
        pk: ipa_pk,
        vk: ipa_vk,
    })
}

pub fn build_client_inputs(
    client_inputs: &mut Vec<ClientInput<VestaConfig>>,
    nullifier_tree: &mut IndexedMerkleTree<Fr, 32>,
    global_comm_roots: &mut Vec<Fr>,
    g_polys: &mut Vec<DensePolynomial<Fq>>,
    client_circuit: &dyn ClientPlonkCircuit<PallasConfig, VestaConfig, VestaConfig>,
    token_id: Option<Fq>,
) -> Result<(), String> {
    let (c, n) = client_circuit.get_commitment_and_nullifier_count();
    let inputs = client_circuit
        .generate_random_inputs(token_id)
        .map_err(|e| e.to_string())?;
    let plonk_circuit = client_circuit
        .to_plonk_circuit(inputs)
        .map_err(|e| e.to_string())?;
    let public_inputs = ClientPubInput::new(
        plonk_circuit.public_input().map_err(|e| e.to_string())?,
        (c, n),
    )
    .map_err(|e| e.to_string())?;
    let artifacts = generate_client_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _>(
        &plonk_circuit,
        true,
    )?;
    let low_nullifier_info = client_input::update_nullifier_tree::<VestaConfig, 32>(
        nullifier_tree,
        &public_inputs.nullifiers,
    );

    let client_input = client_circuit.generate_client_input_for_sequencer(
        artifacts.proof,
        artifacts.vk,
        &public_inputs,
        &low_nullifier_info,
    );
    // TODO: This is only for transfers. Check if OK
    if low_nullifier_info.is_some() {
        global_comm_roots.push(field_switching(&public_inputs.commitment_root[0]));
        //TODO: this is principle is only fot transfers
    }

    g_polys.push(artifacts.g_poly);
    client_inputs.push(client_input);

    Ok(())
}

pub fn build_commit_keys() -> Result<(CommitKey<VestaConfig>, CommitKey<PallasConfig>), String> {
    let mut rng = ChaChaRng::from_entropy();
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

    Ok((vesta_commit_key, pallas_commit_key))
}
