use crate::client::circuits::circuit_inputs::CircuitInputs;
use crate::primitives::circuits::kem_dem::KemDemParams;
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_ff::UniformRand;
use common::{
    crypto::poseidon::constants::PoseidonParams,
    keypair::{PrivateKey, PublicKey},
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use zk_macros::client_bounds;

use super::check_inputs;
#[client_bounds]
pub fn build_random_inputs<P, V, VSW, const C: usize>(
    token_id: Option<V::ScalarField>,
) -> Result<CircuitInputs<P>, CircuitError> {
    let mut rng = ChaChaRng::from_entropy();

    let mut values = Vec::with_capacity(C);
    let mut ids = Vec::with_capacity(C);
    let mut salts = Vec::with_capacity(C);
    let mut recipients = Vec::with_capacity(C);

    let token_id = token_id.unwrap_or_else(|| V::ScalarField::rand(&mut rng));

    for _ in 0..C {
        let pk = PrivateKey::from_scalar(P::ScalarField::rand(&mut rng));
        ids.push(token_id);
        salts.push(V::ScalarField::rand(&mut rng));
        values.push(<<P as CurveConfig>::BaseField>::from(u32::rand(&mut rng)));
        recipients.push(PublicKey::from_private_key(&pk));
    }

    let mut circuit_inputs = CircuitInputs::<P>::new();
    circuit_inputs
        .add_token_values(values)
        .add_token_ids(ids)
        .add_token_salts(salts)
        .add_recipients(recipients)
        .build();
    check_inputs::<P, V>(&circuit_inputs, C)?;

    Ok(circuit_inputs)
}

#[client_bounds]
pub fn build_inputs<P, V, VSW, const C: usize>(
    values: Vec<V::ScalarField>,
    ids: Vec<V::ScalarField>,
    salts: Vec<V::ScalarField>,
    owners: Vec<PublicKey<P>>,
) -> Result<CircuitInputs<P>, CircuitError> {
    let mut circuit_inputs = CircuitInputs::<P>::new();
    circuit_inputs
        .add_token_values(values)
        .add_token_ids(ids)
        .add_token_salts(salts)
        .add_recipients(owners)
        .build();
    check_inputs::<P, V>(&circuit_inputs, C)?;

    Ok(circuit_inputs)
}
