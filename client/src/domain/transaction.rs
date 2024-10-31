use std::fmt::Display;

use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use serde::{Deserialize, Serialize};

use super::{ark_de, ark_se, PublicKey};

#[derive(Clone, Copy, Hash, Debug, Eq, PartialEq)]
pub enum CircuitType {
    Mint,
    Transfer,
    AtomicSwap,
}
impl Display for CircuitType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitType::Mint => write!(f, "Mint"),
            CircuitType::Transfer => write!(f, "Transfer"),
            CircuitType::AtomicSwap => write!(f, "AtomicSwap"),
        }
    }
}

#[derive(
    Derivative, Default, Debug, Serialize, Deserialize, CanonicalSerialize, CanonicalDeserialize,
)]
#[derivative(
    Copy(bound = "EmbedCurve: SWCurveConfig"),
    Clone(bound = "EmbedCurve: SWCurveConfig"),
    PartialEq(bound = "EmbedCurve: SWCurveConfig"),
    Eq(bound = "EmbedCurve: SWCurveConfig"),
    Hash(bound = "EmbedCurve: SWCurveConfig")
)]

pub struct Preimage<EmbedCurve: SWCurveConfig> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) value: EmbedCurve::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) token_id: EmbedCurve::BaseField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) public_key: PublicKey<EmbedCurve>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) salt: EmbedCurve::BaseField,
}

impl<EmbedCurve: SWCurveConfig> Preimage<EmbedCurve> {
    pub fn new(
        value: EmbedCurve::BaseField,
        token_id: EmbedCurve::BaseField,
        public_key: PublicKey<EmbedCurve>,
        salt: EmbedCurve::BaseField,
    ) -> Self {
        Self {
            value,
            token_id,
            public_key,
            salt,
        }
    }
    pub fn get_value(&self) -> &EmbedCurve::BaseField {
        &self.value
    }
    pub fn get_token_id(&self) -> &EmbedCurve::BaseField {
        &self.token_id
    }
    pub fn get_public_key(&self) -> &PublicKey<EmbedCurve> {
        &self.public_key
    }
    pub fn get_salt(&self) -> &EmbedCurve::BaseField {
        &self.salt
    }

    pub fn to_vec<F: PrimeField>(&self) -> Option<Vec<F>>
    where
        EmbedCurve: SWCurveConfig<BaseField = F>,
    {
        self.public_key
            .as_affine()
            .xy()
            .map(|(x, y)| vec![self.value, self.token_id, self.salt, *x, *y])
    }
}
