use crate::client::{
    self,
    circuits::mint::{self, MintCircuit},
    circuits::transfer::{self, TransferCircuit},
};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{ProvingKey, VerifyingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, gadgets::ecc::SWToTEConParam};

use crate::primitives::circuits::kem_dem::KemDemParams;

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
    let mint_inputs = mint::build_random_inputs::<P, V, _, C, N, D>().unwrap();
    let mint_keys =
        client::generate_keys_from_inputs::<P, V, _, C, N, D>(&MintCircuit::new(), mint_inputs)?;
    let transfer_inputs = transfer::build_random_inputs::<P, V, _, C, N, D>().unwrap();
    let transfer_keys = client::generate_keys_from_inputs::<P, V, _, C, N, D>(
        &TransferCircuit::new(),
        transfer_inputs,
    )?;

    Ok(vec![mint_keys, transfer_keys])
}
