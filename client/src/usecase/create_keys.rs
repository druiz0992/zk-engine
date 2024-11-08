use crate::ports::storage::KeyDB;
use crate::{
    adapters::rest_api::structs::MnemonicInput,
    services::user_keys::{generate_user_keys, UserKeys},
};
use anyhow::anyhow;
use ark_ec::{short_weierstrass::SWCurveConfig, CurveConfig};
use ark_ff::PrimeField;
use bip32::Mnemonic;
use common::crypto::poseidon::constants::PoseidonParams;
use std::sync::Arc;
use tokio::sync::Mutex;

pub async fn create_keys_process<P, Storage>(
    db: Arc<Mutex<Storage>>,
    mnemonic_str: MnemonicInput,
) -> anyhow::Result<UserKeys<P>>
where
    P: SWCurveConfig,
    Storage: KeyDB<E = P, Key = UserKeys<P>>,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    let user_keys = create_user_keys_from_mnemonic(mnemonic_str)?;
    store_user_keys(db, user_keys).await?;

    Ok(user_keys)
}

fn create_user_keys_from_mnemonic<P>(mnemonic_str: MnemonicInput) -> anyhow::Result<UserKeys<P>>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    let mnemonic = Mnemonic::new(mnemonic_str.mnemonic, bip32::Language::English)?;
    generate_user_keys::<P>(mnemonic).map_err(|e| anyhow!("Error generating user keys {e}"))
}

async fn store_user_keys<P, Storage>(
    db: Arc<Mutex<Storage>>,
    user_keys: UserKeys<P>,
) -> anyhow::Result<()>
where
    P: SWCurveConfig,
    Storage: KeyDB<E = P, Key = UserKeys<P>>,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    db.lock()
        .await
        .insert_key(user_keys.public_key, user_keys)
        .ok_or(anyhow::anyhow!("User keys could't be inserted in KeyDB"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::rest_api::structs::MnemonicInput;
    use bip39::{Language, Mnemonic};
    use curves::pallas::PallasConfig;
    use itertools::Itertools;

    const MNEMONIC_COUNT: usize = 24;
    #[test]
    fn user_keys_generated_with_corrent_count() {
        let mnemonic = Mnemonic::generate_in(Language::English, MNEMONIC_COUNT).unwrap();
        let input = MnemonicInput {
            mnemonic: mnemonic.words().join(" "),
        };

        let user_keys = create_user_keys_from_mnemonic::<PallasConfig>(input);

        assert!(user_keys.is_ok());
    }
    #[test]
    fn user_keys_not_generated_with_incorrect_count() {
        let mnemonic = Mnemonic::generate_in(Language::English, 15).unwrap();
        let input = MnemonicInput {
            mnemonic: mnemonic.words().join(" "),
        };

        let user_keys = create_user_keys_from_mnemonic::<PallasConfig>(input);

        assert!(user_keys.is_err());
    }

    #[test]
    fn user_keys_not_generated_with_french_mnemonic() {
        let mnemonic = Mnemonic::generate_in(Language::French, MNEMONIC_COUNT).unwrap();
        let input = MnemonicInput {
            mnemonic: mnemonic.words().join(" "),
        };

        let user_keys = create_user_keys_from_mnemonic::<PallasConfig>(input);

        assert!(user_keys.is_err());
    }
}
