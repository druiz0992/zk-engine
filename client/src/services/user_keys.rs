use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bip32::{Mnemonic, XPrv};
use common::crypto::poseidon::constants::PoseidonParams;
use common::derived_keys::DerivedKeys;
use derivative::Derivative;
use jf_utils::field_switching;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use std::convert::From;

use crate::{
    domain::{ark_de, ark_se},
    ports::keys::{FullKey, OwnershipKey, SpendingKey},
};

#[derive(
    Serialize, Deserialize, Derivative, CanonicalSerialize, CanonicalDeserialize, Default, Debug,
)]
#[derivative(
    Copy(bound = "P: SWCurveConfig"),
    Clone(bound = "P: SWCurveConfig"),
    PartialEq(bound = "P: SWCurveConfig"),
    Eq(bound = "P: SWCurveConfig"),
    Hash(bound = "P: SWCurveConfig")
)]

pub struct UserKeys<P: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub root_key: P::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub private_key: P::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub nullifier_key: P::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: Affine<P>,
}

impl<C: SWCurveConfig> SpendingKey<C> for UserKeys<C> {
    fn get_nullifier_key(&self) -> C::BaseField {
        self.nullifier_key
    }
}
impl<C: SWCurveConfig> OwnershipKey<C> for UserKeys<C> {
    fn get_ownership_key(&self) -> C::ScalarField {
        self.private_key
    }
}
impl<C: SWCurveConfig> FullKey<C> for UserKeys<C> {
    fn get_private_key(&self) -> C::BaseField {
        self.root_key
    }
}

pub fn generate_user_keys<P>(mnemonic: Mnemonic) -> Result<UserKeys<P>, bip32::Error>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    let seed = mnemonic.to_seed("");
    let root_key_big_int = BigUint::from_bytes_le(&XPrv::new(&seed)?.to_bytes()[1..]);
    let root_key_fr = P::ScalarField::from(root_key_big_int);
    let root_key = field_switching(&root_key_fr);
    let derived_keys = DerivedKeys::new(root_key).map_err(|_| bip32::Error::Crypto)?;

    Ok(UserKeys {
        root_key,
        private_key: derived_keys.private_key,
        nullifier_key: derived_keys.nullifier_key,
        public_key: derived_keys.public_key,
    })
}

#[cfg(test)]
mod tests {

    use super::*;
    use bip32::Mnemonic;

    use curves::pallas::PallasConfig;

    #[test]
    fn test_generate_valid_keys() {
        let mnemonic_str = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";
        let mnemonic = Mnemonic::new(mnemonic_str, bip32::Language::English).unwrap();
        generate_user_keys::<PallasConfig>(mnemonic).expect("Should be able to generate new keys");
    }

    #[test]
    fn test_serialization() {
        let mnemonic_str = "pact gun essay three dash seat page silent slogan hole huge harvest awesome fault cute alter boss thank click menu service quarter gaze salmon";
        let mnemonic = Mnemonic::new(mnemonic_str, bip32::Language::English).unwrap();
        let keys = generate_user_keys::<PallasConfig>(mnemonic)
            .expect("Should be able to generate new keys");

        let serialized = serde_json::to_string(&keys).expect("Failed to serialize UserKeys");

        // Deserialize back to UserKeys
        let deserialized: UserKeys<PallasConfig> =
            serde_json::from_str(&serialized).expect("Failed to deserialize UserKeys");

        // Assert that the original and deserialized instances are equal
        assert_eq!(keys.root_key, deserialized.root_key);
        assert_eq!(keys.private_key, deserialized.private_key);
        assert_eq!(keys.nullifier_key, deserialized.nullifier_key);
        assert_eq!(keys.public_key, deserialized.public_key);
    }
}
