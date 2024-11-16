use super::*;
use crate::client::PlonkCircuitParams;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::CurveGroup;
use ark_ff::Zero;
use ark_poly::univariate::DensePolynomial;
use ark_std::UniformRand;
use common::crypto::poseidon::Poseidon;
use curves::pallas::Affine as PAffine;
use curves::pallas::{Fq, Fr, PallasConfig};
use curves::vesta::VestaConfig;
use jf_plonk::nightfall::ipa_structs::CommitKey;
use jf_plonk::nightfall::ipa_structs::{ProvingKey, VerifyingKey};
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::UniversalSNARK;
use jf_plonk::transcript::RescueTranscript;
use jf_primitives::pcs::StructuredReferenceString;
use jf_relation::gadgets::ecc::short_weierstrass::SWPoint;
use jf_relation::PlonkCircuit;
use jf_relation::{Arithmetization, Circuit};
use jf_utils::{field_switching, fq_to_fr_with_mask, test_rng};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::ptr::null;
use std::str::FromStr;
use trees::membership_tree::{MembershipTree, Tree};
use trees::non_membership_tree::IndexedMerkleTree;
use trees::non_membership_tree::NonMembershipTree;
use trees::tree::AppendTree;
use trees::MembershipPath;
use zk_macros::{client_circuit, sequencer_circuit};

use crate::client::circuits::mint;
use crate::client::circuits::swap::swap_circuit;
use crate::client::circuits::transfer;

use crate::primitives::circuits::kem_dem::KemDemParams;
use crate::rollup::circuits::base::BasePublicVarIndex;
use crate::rollup::circuits::client_input::{self, LowNullifierInfo};
use crate::rollup::circuits::structs::{AccInstance, GlobalPublicInputs, SubTrees};
use crate::rollup::circuits::utils::StoredProof;
use crate::utils::bench::tree::tree_generator_from_client_inputs;
use ark_ec::short_weierstrass::Affine;
use ark_ec::short_weierstrass::Projective;
use ark_ec::CurveConfig;
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::Proof;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;

use super::{base_rollup_circuit, ClientInput};

#[derive(Clone)]
pub(crate) enum TransactionType {
    Mint,
    Transfer,
}

#[client_circuit]
pub(crate) fn generate_client_circuit_artifacts_and_verify<P, V, VSW>(
    circuit: &PlonkCircuit<V::ScalarField>,
    verify_flag: bool,
) -> Result<
    (
        Proof<V>,
        DensePolynomial<V::ScalarField>,
        ProvingKey<V>,
        VerifyingKey<V>,
    ),
    String,
> {
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
    Ok((ipa_proof, g_poly, ipa_pk, ipa_vk))
}

#[sequencer_circuit]
pub(crate) fn generate_base_circuit_artifacts_and_verify<P, V, SW, VSW>(
    base_circuit: &PlonkCircuit<P::ScalarField>,
    verify_flag: bool,
) -> Result<
    (
        Proof<P>,
        DensePolynomial<P::ScalarField>,
        ProvingKey<P>,
        VerifyingKey<P>,
    ),
    String,
> {
    let mut rng = ChaChaRng::from_entropy();
    let srs_size = base_circuit
        .srs_size()
        .map_err(|_| "Couldnt extract Base Circuit SRS Size".to_string())?;
    let base_ipa_srs =
        <PlonkIpaSnark<P> as UniversalSNARK<P>>::universal_setup_for_testing(srs_size, &mut rng)
            .map_err(|_| "Couldnt compute Base Circuit SRS")?;

    let (base_ipa_pk, base_ipa_vk) = PlonkIpaSnark::<P>::preprocess(&base_ipa_srs, base_circuit)
        .map_err(|_| "Couldn't compute Base Circuit PK/VK".to_string())?;

    let now = std::time::Instant::now();
    let (base_ipa_proof, g_poly, _) = PlonkIpaSnark::<P>::prove_for_partial::<
        _,
        _,
        RescueTranscript<P::BaseField>,
    >(&mut rng, base_circuit, &base_ipa_pk, None)
    .map_err(|_| "Couldn't compute Base Circuit Proof".to_string())?;
    ark_std::println!("Proving time: {}", now.elapsed().as_secs());

    if verify_flag {
        PlonkIpaSnark::<P>::verify::<RescueTranscript<P::BaseField>>(
            &base_ipa_vk,
            &base_circuit.public_input().unwrap(),
            &base_ipa_proof,
            None,
        )
        .map_err(|_| "Couldn't verify Base Circuit Proof".to_string())?;
        ark_std::println!("Base Circuit proof verified");
    }

    Ok((base_ipa_proof, g_poly, base_ipa_pk, base_ipa_vk))
}

pub(crate) fn generate_circuit_params<const D: usize>(
    transaction_type_selector: TransactionType,
    transaction_inputs_selector: usize,
    token_id: Option<Fq>,
) -> (PlonkCircuitParams<Fq>, usize, usize) {
    match transaction_inputs_selector % 2 {
        0 => {
            const C: usize = 1;
            const N: usize = 1;
            let circuit_params = match transaction_type_selector {
                TransactionType::Mint => {
                    mint::utils::mint_with_random_inputs::<PallasConfig, VestaConfig, _, C>(
                        token_id,
                    )
                    .unwrap()
                }
                TransactionType::Transfer => transfer::utils::transfer_with_random_inputs::<
                    PallasConfig,
                    VestaConfig,
                    _,
                    C,
                    N,
                    D,
                >(token_id)
                .unwrap(),
            };
            (circuit_params, C, N)
        }
        1 => {
            const C: usize = 1;
            const N: usize = 4;
            let circuit_params = match transaction_type_selector {
                TransactionType::Mint => {
                    mint::utils::mint_with_random_inputs::<PallasConfig, VestaConfig, _, C>(
                        token_id,
                    )
                    .unwrap()
                }
                TransactionType::Transfer => transfer::utils::transfer_with_random_inputs::<
                    PallasConfig,
                    VestaConfig,
                    _,
                    C,
                    N,
                    D,
                >(token_id)
                .unwrap(),
            };
            (circuit_params, C, N)
        }
        _ => unimplemented!(),
    }
}

pub(crate) fn build_client_inputs_for_mint<const D: usize>(
    client_inputs: &mut Vec<ClientInput<VestaConfig, D>>,
    global_comm_roots: &mut Vec<Fr>,
    g_polys: &mut Vec<DensePolynomial<Fq>>,
    transaction_inputs_selector: usize,
    token_id: Option<Fq>,
) -> Result<(), String> {
    let (mint_circuit_params, mint_n_commitments, mint_n_nullifiers) =
        generate_circuit_params::<D>(TransactionType::Mint, transaction_inputs_selector, token_id);
    let (mint_ipa_proof, g_poly, _mint_ipa_pk, mint_ipa_vk) =
        generate_client_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _>(
            &mint_circuit_params.circuit,
            true,
        )?;

    let mut client_input = ClientInput::<VestaConfig, D>::new(
        mint_ipa_proof,
        mint_ipa_vk.clone(),
        mint_n_commitments,
        1,
    );
    let public_inputs = mint_circuit_params.public_inputs;

    client_input.set_commitments(&public_inputs.commitments);
    //.set_commitment_tree_root(&public_inputs.commitment_root);
    client_inputs.push(client_input);
    g_polys.push(g_poly);
    //global_comm_roots.push(field_switching(&public_inputs.commitment_root[0]));

    Ok(())
}

pub(crate) fn build_client_inputs_for_transfer<const D: usize>(
    client_inputs: &mut Vec<ClientInput<VestaConfig, D>>,
    nullifier_tree: &mut IndexedMerkleTree<Fr, 32>,
    global_comm_roots: &mut Vec<Fr>,
    g_polys: &mut Vec<DensePolynomial<Fq>>,
    transaction_inputs_selector: usize,
    token_id: Option<Fq>,
) -> Result<(), String> {
    let (transfer_circuit_params, n_commitments, n_nullifiers) = generate_circuit_params::<D>(
        TransactionType::Transfer,
        transaction_inputs_selector,
        token_id,
    );
    let (transfer_ipa_proof, g_poly, _transfer_ipa_pk, transfer_ipa_vk) =
        generate_client_circuit_artifacts_and_verify::<PallasConfig, VestaConfig, _>(
            &transfer_circuit_params.circuit,
            true,
        )?;

    let mut client_input = ClientInput::<VestaConfig, D>::new(
        transfer_ipa_proof,
        transfer_ipa_vk.clone(),
        n_commitments,
        n_nullifiers,
    );
    let public_inputs = transfer_circuit_params.public_inputs;

    let low_nullifier_info = client_input::update_nullifier_tree::<VestaConfig, 32>(
        nullifier_tree,
        &public_inputs.nullifiers,
    );

    client_input
        .set_nullifiers(&public_inputs.nullifiers)
        .set_commitments(&public_inputs.commitments)
        .set_commitment_tree_root(&public_inputs.commitment_root)
        .set_low_nullifier_info(&low_nullifier_info)
        .set_eph_pub_key(
            client_input::to_eph_key_array::<VestaConfig>(public_inputs.ephemeral_public_key)
                .unwrap(),
        )
        .set_ciphertext(
            client_input::to_ciphertext_array::<VestaConfig>(public_inputs.ciphertexts).unwrap(),
        );

    g_polys.push(g_poly);
    client_inputs.push(client_input);
    global_comm_roots.push(field_switching(&public_inputs.commitment_root[0]));

    Ok(())
}

pub(crate) fn build_client_inputs<const D: usize>(
    client_inputs: &mut Vec<ClientInput<VestaConfig, D>>,
    nullifier_tree: &mut IndexedMerkleTree<Fr, 32>,
    global_comm_roots: &mut Vec<Fr>,
    g_polys: &mut Vec<DensePolynomial<Fq>>,
    transaction_type_selector: &TransactionType,
    transaction_inputs_selector: usize,
    token_id: Option<Fq>,
) -> Result<(), String> {
    match transaction_type_selector {
        TransactionType::Mint => build_client_inputs_for_mint(
            client_inputs,
            global_comm_roots,
            g_polys,
            transaction_inputs_selector,
            token_id,
        ),
        TransactionType::Transfer => build_client_inputs_for_transfer(
            client_inputs,
            nullifier_tree,
            global_comm_roots,
            g_polys,
            transaction_inputs_selector,
            token_id,
        ),
    }
}

pub(crate) fn build_commit_keys(
) -> Result<(CommitKey<VestaConfig>, CommitKey<PallasConfig>), String> {
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
