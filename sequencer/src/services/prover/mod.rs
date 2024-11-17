use crate::domain::RollupCommitKeys;
use crate::ports::prover::SequencerProver;
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, Projective, SWCurveConfig};
use ark_ec::{CurveConfig, CurveGroup};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::VerifyingKey;
use jf_plonk::nightfall::PlonkIpaSnark;
use jf_plonk::proof_system::UniversalSNARK;
use jf_primitives::pcs::StructuredReferenceString;
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use plonk_prover::client::ClientPlonkCircuit;
use plonk_prover::primitives::circuits::kem_dem::KemDemParams;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zk_macros::sequencer_circuit;

pub mod in_mem_sequencer_prover;

#[sequencer_circuit]
pub fn generate_and_store_cks<V, VSW, P, SW, Prover>(prover: &mut Prover)
where
    Prover: SequencerProver<V, VSW, P, SW>,
{
    let mut rng = ChaChaRng::from_entropy();
    let vesta_srs = <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(
        2usize.pow(20),
        &mut rng,
    )
    .unwrap();
    let (vesta_commit_key, _) = vesta_srs.trim(2usize.pow(20)).unwrap();

    let pallas_srs = <PlonkIpaSnark<P> as UniversalSNARK<P>>::universal_setup_for_testing(
        2usize.pow(20),
        &mut rng,
    )
    .unwrap();
    let (pallas_commit_key, _) = pallas_srs.trim(2usize.pow(20)).unwrap();
    let rollup_commit_keys = RollupCommitKeys {
        pallas_commit_key,
        vesta_commit_key,
    };
    prover.store_cks(rollup_commit_keys);
}

pub fn generate_and_store_client_circuit_vks<P, V, SW, VSW, Prover>(
    prover: &mut Prover,
    circuit_info: Vec<Box<dyn ClientPlonkCircuit<P, V, VSW>>>,
) -> Vec<VerifyingKey<V>>
where
    V: Pairing<
        G1Affine = Affine<VSW>,
        G1 = Projective<VSW>,
        ScalarField = <P as CurveConfig>::BaseField,
    >,
    <V as Pairing>::BaseField: PrimeField
        + PoseidonParams<Field = <P as Pairing>::ScalarField>
        + RescueParameter
        + SWToTEConParam,
    <V as Pairing>::ScalarField: PrimeField
        + PoseidonParams<Field = <P as Pairing>::BaseField>
        + RescueParameter
        + SWToTEConParam,
    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,

    P: Pairing<G1Affine = Affine<SW>, G1 = Projective<SW>>
        + SWCurveConfig
        + Pairing<BaseField = <V as Pairing>::ScalarField, ScalarField = <V as Pairing>::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,

    SW: SWCurveConfig<
        BaseField = <V as Pairing>::ScalarField,
        ScalarField = <V as Pairing>::BaseField,
    >,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
    Prover: SequencerProver<V, VSW, P, SW>,
{
    circuit_info
        .into_iter()
        .map(|c| {
            let keys = c.generate_keys().unwrap();
            prover.store_vk(c.get_circuit_id(), keys.1.clone());
            keys.1
        })
        .collect::<Vec<VerifyingKey<_>>>()
}
