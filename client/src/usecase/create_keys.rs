use crate::{
    adapters::rest_api::structs::MnemonicInput,
    services::user_keys::{generate_user_keys, UserKeys},
};
use anyhow::anyhow;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::PrimeField;
use bip32::Mnemonic;
use common::crypto::poseidon::constants::PoseidonParams;

pub fn create_user_keys_from_mnemonic<P>(
    mnemonic_str: MnemonicInput,
) -> Result<UserKeys<P>, anyhow::Error>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    let mnemonic = Mnemonic::new(mnemonic_str.mnemonic, bip32::Language::English)?;
    generate_user_keys::<P>(mnemonic).map_err(|e| anyhow!("Error generating user keys {e}"))
}
