use std::fmt::Display;

use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveConfig, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;
use jf_plonk::nightfall::ipa_structs::Proof;
use serde::{Deserialize, Serialize};

use super::{ark_de, ark_se, ECurve, Fr, PublicKey};

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

#[derive(Derivative, Default, Debug)]
#[derivative(
    Clone(bound = "E: SWCurveConfig"),
    PartialEq(bound = "E: SWCurveConfig"),
    Eq(bound = "E: SWCurveConfig"),
    Hash(bound = "E: SWCurveConfig")
)]

pub struct CircuitInputs<E>
where
    E: SWCurveConfig,
{
    pub token_values: Vec<E::BaseField>,
    pub token_ids: Vec<E::BaseField>,
    pub token_salts: Vec<E::BaseField>,
    pub recipients: Vec<PublicKey<E>>,
    pub old_token_values: Vec<E::BaseField>,
    pub old_token_salts: Vec<E::BaseField>,
    pub membership_path: Vec<Vec<E::BaseField>>,
    pub commitment_tree_root: Vec<E::BaseField>,
    pub membership_path_index: Vec<E::BaseField>,
    pub root_key: E::BaseField,
    pub ephemeral_key: E::BaseField,
}

impl<E> CircuitInputs<E>
where
    E: SWCurveConfig,
{
    pub fn new() -> Self {
        Self {
            token_values: Vec::new(),
            token_ids: Vec::new(),
            token_salts: Vec::new(),
            recipients: Vec::new(),
            old_token_values: Vec::new(),
            old_token_salts: Vec::new(),
            membership_path: Vec::new(),
            commitment_tree_root: Vec::new(),
            membership_path_index: Vec::new(),
            root_key: E::BaseField::zero(),
            ephemeral_key: E::BaseField::zero(),
        }
    }
    pub fn build(&self) -> Self {
        Self {
            token_values: self.token_values.clone(),
            token_ids: self.token_ids.clone(),
            token_salts: self.token_salts.clone(),
            recipients: self.recipients.clone(),
            old_token_values: self.old_token_values.clone(),
            old_token_salts: self.old_token_salts.clone(),
            commitment_tree_root: self.commitment_tree_root.clone(),
            membership_path: self.membership_path.clone(),
            membership_path_index: self.membership_path_index.clone(),
            root_key: self.root_key,
            ephemeral_key: self.ephemeral_key,
        }
    }
    pub fn add_token_values(&mut self, token_value: Vec<E::BaseField>) -> &mut Self {
        self.token_values = token_value;
        self
    }
    pub fn add_commitment_tree_root(&mut self, root: Vec<E::BaseField>) -> &mut Self {
        self.commitment_tree_root = root;
        self
    }
    pub fn add_token_ids(&mut self, token_id: Vec<E::BaseField>) -> &mut Self {
        self.token_ids = token_id;
        self
    }
    pub fn add_token_salts(&mut self, salts: Vec<E::BaseField>) -> &mut Self {
        self.token_salts = salts;
        self
    }
    pub fn add_recipients(&mut self, recipients: Vec<PublicKey<E>>) -> &mut Self {
        self.recipients = recipients;
        self
    }
    pub fn add_old_token_values(&mut self, old_token_values: Vec<E::BaseField>) -> &mut Self {
        self.old_token_values = old_token_values;
        self
    }
    pub fn add_old_token_salts(&mut self, old_token_salts: Vec<E::BaseField>) -> &mut Self {
        self.old_token_salts = old_token_salts;
        self
    }
    pub fn add_membership_path(&mut self, membership_path: Vec<Vec<E::BaseField>>) -> &mut Self {
        self.membership_path = membership_path;
        self
    }
    pub fn add_membership_path_index(
        &mut self,
        membership_path_index: Vec<E::BaseField>,
    ) -> &mut Self {
        self.membership_path_index = membership_path_index;
        self
    }
    pub fn add_ephemeral_key(&mut self, ephemeral_key: E::BaseField) -> &mut Self {
        self.ephemeral_key = ephemeral_key;
        self
    }
    pub fn add_root_key(&mut self, root_key: E::BaseField) -> &mut Self {
        self.root_key = root_key;
        self
    }
}

#[derive(Clone, Deserialize, Serialize, Default, Debug)]
pub struct Commitment<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

impl<F: PrimeField> From<F> for Commitment<F> {
    fn from(value: F) -> Self {
        Commitment(value)
    }
}

#[derive(Clone, Deserialize, Serialize, Default)]
pub struct Nullifier<F: PrimeField>(
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] pub F,
);

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
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Transaction<P: Pairing>
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub(crate) commitments: Vec<Commitment<P::ScalarField>>,
    pub(crate) nullifiers: Vec<Nullifier<P::ScalarField>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) ciphertexts: Vec<P::ScalarField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) proof: Proof<P>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) g_polys: DensePolynomial<P::ScalarField>,
}

impl<P: Pairing> Transaction<P>
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    pub fn new(
        commitments: Vec<Commitment<P::ScalarField>>,
        nullifiers: Vec<Nullifier<P::ScalarField>>,
        ciphertexts: Vec<P::ScalarField>,
        proof: Proof<P>,
        g_polys: DensePolynomial<P::ScalarField>,
    ) -> Self {
        Self {
            commitments,
            nullifiers,
            ciphertexts,
            proof,
            g_polys,
        }
    }
}
