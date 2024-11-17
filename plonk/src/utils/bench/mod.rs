use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use ark_poly::univariate::DensePolynomial;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{Proof, ProvingKey, VerifyingKey};
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::UniversalSNARK;
use jf_plonk::transcript::RescueTranscript;
use jf_primitives::rescue::RescueParameter;
use jf_relation::{gadgets::ecc::SWToTEConParam, Arithmetization, Circuit, PlonkCircuit};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zk_macros::sequencer_circuit;

pub mod base;
pub mod bounce;
pub mod merge;
pub mod tree;

pub struct RollupCircuitArtifacts<P>
where
    P: Pairing,
    <P::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub proof: Proof<P>,
    pub g_poly: DensePolynomial<P::ScalarField>,
    pub pk: ProvingKey<P>,
    pub vk: VerifyingKey<P>,
}

#[sequencer_circuit]
pub fn generate_rollup_circuit_artifacts_and_verify<P, V, SW, VSW>(
    rollup_circuit: &PlonkCircuit<P::ScalarField>,
    verify_flag: bool,
) -> Result<RollupCircuitArtifacts<P>, String> {
    let (rollup_ipa_pk, rollup_ipa_vk) =
        generate_rollup_circuit_pks::<P, V, SW, VSW>(rollup_circuit)?;
    let (rollup_ipa_proof, g_poly) = rollup_circuit_proof_and_verify::<P, V, SW, VSW>(
        rollup_circuit,
        &rollup_ipa_pk,
        &rollup_ipa_vk,
        verify_flag,
    )?;

    Ok(RollupCircuitArtifacts {
        proof: rollup_ipa_proof,
        g_poly,
        pk: rollup_ipa_pk,
        vk: rollup_ipa_vk,
    })
}

#[sequencer_circuit]
pub fn generate_rollup_circuit_pks<P, V, SW, VSW>(
    rollup_circuit: &PlonkCircuit<P::ScalarField>,
) -> Result<(ProvingKey<P>, VerifyingKey<P>), String> {
    let mut rng = ChaChaRng::from_entropy();

    let srs_size = rollup_circuit
        .srs_size()
        .map_err(|_| "Couldnt extract rollup Circuit SRS Size".to_string())?;
    let rollup_ipa_srs =
        <PlonkIpaSnark<P> as UniversalSNARK<P>>::universal_setup_for_testing(srs_size, &mut rng)
            .map_err(|_| "Couldnt compute rollup Circuit SRS")?;

    let (rollup_ipa_pk, rollup_ipa_vk) =
        PlonkIpaSnark::<P>::preprocess(&rollup_ipa_srs, rollup_circuit)
            .map_err(|_| "Couldn't compute rollup Circuit PK/VK".to_string())?;

    Ok((rollup_ipa_pk, rollup_ipa_vk))
}

#[sequencer_circuit]
pub fn rollup_circuit_proof_and_verify<P, V, SW, VSW>(
    rollup_circuit: &PlonkCircuit<P::ScalarField>,
    rollup_ipa_pk: &ProvingKey<P>,
    rollup_ipa_vk: &VerifyingKey<P>,
    verify_flag: bool,
) -> Result<(Proof<P>, DensePolynomial<P::ScalarField>), String> {
    let mut rng = ChaChaRng::from_entropy();
    let now = std::time::Instant::now();
    let (rollup_ipa_proof, g_poly, _) = PlonkIpaSnark::<P>::prove_for_partial::<
        _,
        _,
        RescueTranscript<P::BaseField>,
    >(&mut rng, rollup_circuit, rollup_ipa_pk, None)
    .map_err(|_| "Couldn't compute rollup Circuit Proof".to_string())?;
    ark_std::println!("Proving time: {}", now.elapsed().as_secs());

    if verify_flag {
        PlonkIpaSnark::<P>::verify::<RescueTranscript<P::BaseField>>(
            rollup_ipa_vk,
            &rollup_circuit.public_input().unwrap(),
            &rollup_ipa_proof,
            None,
        )
        .map_err(|_| "Couldn't verify rollup Circuit Proof".to_string())?;
        ark_std::println!("rollup Circuit proof verified");
    }

    Ok((rollup_ipa_proof, g_poly))
}
