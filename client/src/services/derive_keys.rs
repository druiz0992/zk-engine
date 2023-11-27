use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::str::FromStr;
use bip32::{Mnemonic, XPrv};
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

use crate::domain::{ark_de, ark_se};

/// Prefix for hashes for zkp private ket and nullifier
/// PRIVATE_KEY_PREFIX = keccak256('zkpPrivateKey'), need to update for Pasta
const PRIVATE_KEY_PREFIX: &str =
    "2708019456231621178814538244712057499818649907582893776052749473028258908910";
/// PRIVATE_KEY_PREFIX = keccak256('nullifierKey'), need to update for Pasta
const NULLIFIER_PREFIX: &str =
    "7805187439118198468809896822299973897593108379494079213870562208229492109015";

#[derive(Clone, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize)]
pub struct UserKeys<P: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    root_key: P::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    private_key: P::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    nullifier_key: P::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    public_key: Affine<P>,
}

pub fn generate_keys<P>(mnemonic: Mnemonic) -> Result<UserKeys<P>, bip32::Error>
where
    P: SWCurveConfig,
    <P as CurveConfig>::ScalarField: PoseidonParams<Field = <P as CurveConfig>::ScalarField>,
{
    let poseidon = Poseidon::<P::ScalarField>::new();
    let seed = mnemonic.to_seed("");
    let root_key_big_int = BigUint::from_bytes_le(&XPrv::new(&seed)?.to_bytes()[1..]);
    let root_key = P::ScalarField::from(root_key_big_int);
    let pk_prefix =
        P::ScalarField::from_str(PRIVATE_KEY_PREFIX).map_err(|_| bip32::Error::Crypto)?;
    let nullifier_prefix =
        P::ScalarField::from_str(NULLIFIER_PREFIX).map_err(|_| bip32::Error::Crypto)?;
    let private_key = poseidon.hash_unchecked(vec![pk_prefix, root_key]);
    let nullifier_key = poseidon.hash_unchecked(vec![nullifier_prefix, root_key]);
    let public_key = (P::GENERATOR * private_key).into_affine();

    Ok(UserKeys {
        root_key,
        private_key,
        nullifier_key,
        public_key,
    })
}
