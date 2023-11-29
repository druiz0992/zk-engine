use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::{PrimeField, Zero};
use ark_std::str::FromStr;
use ark_std::UniformRand;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use jf_plonk::{
    nightfall::{ipa_structs::ProvingKey, PlonkIpaSnark},
    proof_system::UniversalSNARK,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam, Arithmetization};
use jf_utils::field_switching;
use num_bigint::BigUint;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use crate::{
    client::circuits::{mint::mint_circuit, transfer::transfer_circuit},
    primitives::circuits::kem_dem::KemDemParams,
};

pub fn generate_client_pks_and_vks<P, V, VSW>() -> Result<Vec<ProvingKey<V>>, CircuitError>
where
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,

    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
{
    let mink_vk = dummy_mint::<P, V, VSW, 1>()?;
    let transfer_vk = dummy_transfer::<P, V, VSW, 2>()?;
    Ok(vec![mink_vk, transfer_vk])
}

fn dummy_mint<P, V, VSW, const OUT: usize>() -> Result<ProvingKey<V>, CircuitError>
where
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,

    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
{
    let value = V::ScalarField::zero();
    let token_id = V::ScalarField::zero();
    let token_nonce = V::ScalarField::zero();
    let secret_key = V::ScalarField::from(1u64);
    let secret_key_fr = field_switching::<V::ScalarField, P::ScalarField>(&secret_key);
    let token_owner = (P::GENERATOR * secret_key_fr).into_affine();
    let mut circuit = mint_circuit::<P, V, 1>([value], [token_id], [token_nonce], [token_owner])?;
    circuit.finalize_for_arithmetization().unwrap();

    let srs_size = circuit.srs_size().unwrap();
    let mut rng = ChaChaRng::from_entropy();
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;

    let (pk, _) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit).unwrap();
    Ok(pk)
}

fn dummy_transfer<P, V, VSW, const WIDTH: usize>() -> Result<ProvingKey<V>, CircuitError>
where
    V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
    <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,

    <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,
    VSW: SWCurveConfig<
        BaseField = <V as Pairing>::BaseField,
        ScalarField = <V as Pairing>::ScalarField,
    >,
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
{
    let mut rng = ChaChaRng::from_entropy();
    let root_key = V::ScalarField::rand(&mut rng);
    const PRIVATE_KEY_PREFIX: &str =
        "2708019456231621178814538244712057499818649907582893776052749473028258908910";
    const NULLIFIER_PREFIX: &str =
        "7805187439118198468809896822299973897593108379494079213870562208229492109015";

    let private_key_domain = P::BaseField::from_str(PRIVATE_KEY_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;
    let nullifier_key_domain = P::BaseField::from_str(NULLIFIER_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;

    let private_key = Poseidon::<V::ScalarField>::new()
        .hash(vec![root_key, private_key_domain])
        .unwrap();
    let private_key_bn: BigUint = private_key.into();
    let mut private_key_bytes = private_key_bn.to_bytes_le();
    private_key_bytes.truncate(31);
    let private_key_trunc = P::ScalarField::from_le_bytes_mod_order(&private_key_bytes);

    let old_commitment_leaf_index = 0u64;

    let value = V::ScalarField::from(1u64);
    let token_id = V::ScalarField::from(2u64);
    let token_nonce = V::ScalarField::from(3u32);
    let token_owner = (P::GENERATOR * private_key_trunc).into_affine();
    let old_commitment_hash = Poseidon::<V::ScalarField>::new()
        .hash(vec![
            value,
            token_id,
            token_nonce,
            token_owner.x,
            token_owner.y,
        ])
        .unwrap();

    let old_commitment_sibling_path = (0..8)
        .map(|_| V::ScalarField::rand(&mut rng))
        .collect::<Vec<_>>();

    let root = old_commitment_sibling_path
        .clone()
        .into_iter()
        .enumerate()
        .fold(old_commitment_hash, |a, (i, b)| {
            let poseidon: Poseidon<V::ScalarField> = Poseidon::new();
            let bit_dir = old_commitment_leaf_index >> i & 1;
            if bit_dir == 0 {
                poseidon.hash(vec![a, b]).unwrap()
            } else {
                poseidon.hash(vec![b, a]).unwrap()
            }
        });

    let recipient_public_key = Affine::rand(&mut rng);
    let ephemeral_key = V::ScalarField::rand(&mut rng);

    let mut circuit = transfer_circuit::<P, V, 1, 1, 8>(
        [value],
        [token_nonce],
        [old_commitment_sibling_path.try_into().unwrap()],
        [V::ScalarField::from(old_commitment_leaf_index)],
        [root],
        [value],
        [V::ScalarField::from(old_commitment_leaf_index)],
        token_id,
        recipient_public_key,
        root_key,
        ephemeral_key,
        private_key_domain,
        nullifier_key_domain,
    )?;
    circuit.finalize_for_arithmetization()?;
    let srs_size = circuit.srs_size()?;
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;
    let (pk, _) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit)?;
    Ok(pk)
}
