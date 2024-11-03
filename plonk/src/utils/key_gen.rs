use crate::client::circuits::transfer::TransferCircuit;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{PrimeField, Zero};
use ark_std::UniformRand;
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use common::keypair::{PrivateKey, PublicKey};
use jf_plonk::{
    nightfall::{
        ipa_structs::{ProvingKey, VerifyingKey},
        PlonkIpaSnark,
    },
    proof_system::UniversalSNARK,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam, Arithmetization};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use trees::MembershipPath;

use crate::{
    client::circuits::{circuit_inputs::CircuitInputs, mint::mint_circuit},
    primitives::circuits::kem_dem::KemDemParams,
};

#[allow(clippy::type_complexity)]
pub fn generate_client_pks_and_vks<P, V, VSW, const C: usize, const D: usize, const N: usize>(
) -> Result<Vec<(ProvingKey<V>, VerifyingKey<V>)>, CircuitError>
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
    let mink_vk = dummy_mint::<P, V, VSW, C, N, D>()?;
    let transfer_vk = dummy_transfer::<P, V, VSW, C, N, D>()?;
    Ok(vec![mink_vk, transfer_vk])
}

fn generate_dummy_mint_inputs<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> CircuitInputs<P, C, N, D>
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
    let value = vec![V::ScalarField::zero()];
    let token_id = vec![V::ScalarField::zero()];
    let token_salt = vec![V::ScalarField::zero()];
    let pk = PrivateKey::from_scalar(P::ScalarField::from(1u64));
    let public_key = vec![PublicKey::from_private_key(&pk)];

    let mut circuit_inputs_builder = CircuitInputs::<P, C, N, D>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_values(value)
        .add_token_ids(token_id)
        .add_token_salts(token_salt)
        .add_recipients(public_key)
        .build();

    circuit_inputs
}
fn dummy_mint<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError>
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
    let circuit_inputs = generate_dummy_mint_inputs::<P, V, VSW, C, N, D>();
    let mut circuit = mint_circuit::<P, V, _, C, N, D>(circuit_inputs)?;
    circuit.finalize_for_arithmetization().unwrap();

    let srs_size = circuit.srs_size().unwrap();
    let mut rng = ChaChaRng::from_entropy();
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;

    let (pk, vk) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit).unwrap();
    Ok((pk, vk))
}

fn generate_dummy_transfer_inputs<P, V, VSW>(token_owner: Affine<P>) -> CircuitInputs<P, 1, 1, 8>
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

    let old_commitment_leaf_index = 0u64;

    let value = V::ScalarField::from(1u64);
    let token_id = V::ScalarField::from(2u64);
    let token_nonce = V::ScalarField::from(3u32);
    let old_commitment_hash = Poseidon::<V::ScalarField>::new()
        .hash(vec![
            value,
            token_id,
            token_nonce,
            token_owner.x,
            token_owner.y,
        ])
        .unwrap();

    let mut old_commitment_sibling_path = MembershipPath::new();
    (0..8).for_each(|_| old_commitment_sibling_path.append(V::ScalarField::rand(&mut rng)));

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

    let pk = PrivateKey::from_scalar(P::ScalarField::from(1u64));
    let public_key = vec![PublicKey::from_private_key(&pk)];
    let ephemeral_key = V::ScalarField::rand(&mut rng);
    let mut circuit_inputs_builder = CircuitInputs::<P, 1, 1, 8>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_values(vec![value])
        .add_token_ids(vec![token_id])
        .add_old_token_values(vec![value])
        .add_old_token_salts(vec![token_nonce])
        .add_root_key(root_key)
        .add_ephemeral_key(ephemeral_key)
        .add_commitment_tree_root(vec![root])
        .add_membership_path(vec![old_commitment_sibling_path])
        .add_membership_path_index(vec![V::ScalarField::from(old_commitment_leaf_index)])
        .add_token_salts(vec![V::ScalarField::from(old_commitment_leaf_index)]) //only the first salt needs to be the index
        .add_recipients(public_key)
        .build();
    circuit_inputs
}

use crate::client::circuits::transfer;
use crate::client::generate_keys_from_inputs;

fn dummy_transfer<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError>
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
    let inputs = transfer::build_random_inputs::<P, V, _, C, N, D>().unwrap();
    let circuit = TransferCircuit::new();
    generate_keys_from_inputs::<P, V, _, C, N, D>(&circuit, inputs)
}
