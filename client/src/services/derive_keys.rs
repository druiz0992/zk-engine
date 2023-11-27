use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::str::FromStr;
use bip32::{Mnemonic, XPrv};
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use derivative::Derivative;
use jf_utils::{field_switching, fq_to_fr_with_mask};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::{
    domain::{ark_de, ark_se},
    ports::keys::{FullKey, OwnershipKey, SpendingKey},
};

/// Prefix for hashes for zkp private ket and nullifier
/// PRIVATE_KEY_PREFIX = keccak256('zkpPrivateKey'), need to update for Pasta
const PRIVATE_KEY_PREFIX: &str =
    "2708019456231621178814538244712057499818649907582893776052749473028258908910";
/// PRIVATE_KEY_PREFIX = keccak256('nullifierKey'), need to update for Pasta
const NULLIFIER_PREFIX: &str =
    "7805187439118198468809896822299973897593108379494079213870562208229492109015";

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

pub fn generate_keys<P>(mnemonic: Mnemonic) -> Result<UserKeys<P>, bip32::Error>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    let poseidon = Poseidon::<P::BaseField>::new();
    let seed = mnemonic.to_seed("");
    let root_key_big_int = BigUint::from_bytes_le(&XPrv::new(&seed)?.to_bytes()[1..]);
    let root_key_fr = P::ScalarField::from(root_key_big_int);
    let root_key = field_switching(&root_key_fr);
    let pk_prefix = P::BaseField::from_str(PRIVATE_KEY_PREFIX).map_err(|_| bip32::Error::Crypto)?;
    let nullifier_prefix =
        P::BaseField::from_str(NULLIFIER_PREFIX).map_err(|_| bip32::Error::Crypto)?;
    let private_key = poseidon.hash_unchecked(vec![root_key, pk_prefix]);
    let private_key_bn: BigUint = private_key.into();
    let mut private_key_bytes = private_key_bn.to_bytes_le();
    private_key_bytes.truncate(31);
    let private_key_trunc = P::ScalarField::from_le_bytes_mod_order(&private_key_bytes);
    let nullifier_key = poseidon.hash_unchecked(vec![root_key, nullifier_prefix]);
    let public_key = (P::GENERATOR * private_key_trunc).into_affine();

    Ok(UserKeys {
        root_key,
        private_key: private_key_trunc,
        nullifier_key,
        public_key,
    })
}
