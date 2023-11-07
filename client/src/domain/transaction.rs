use ark_ec::{pairing::Pairing, CurveGroup};
use ark_ff::PrimeField;

use super::{ECurve, Fr, Proof, PublicKey};

pub enum CircuitType {
    Mint,
    Transfer,
    AtomicSwap,
}

pub struct CircuitInputs<E>
where
    E: Pairing,
{
    token_values: Vec<E::BaseField>,
    token_ids: Vec<E::BaseField>,
    token_salts: Vec<E::BaseField>,
    recipients: Vec<PublicKey<E>>,
    commitment_tree_root: E::BaseField,
    sibling_path: Vec<E::BaseField>,
}

impl<E> CircuitInputs<E>
where
    E: Pairing,
{
    pub fn new() -> Self {
        Self {
            token_values: Vec::new(),
            token_ids: Vec::new(),
            token_salts: Vec::new(),
            recipients: Vec::new(),
            commitment_tree_root: E::BaseField::default(),
            sibling_path: Vec::new(),
        }
    }
    pub fn build(&mut self) -> Self {
        todo!();
    }
    pub fn add_token_values(&mut self, token_value: Vec<E::BaseField>) -> &mut Self {
        todo!();
    }
    pub fn add_commitment_tree_root(&mut self, root: E::BaseField) -> &mut Self {
        todo!()
    }
    pub fn add_token_ids(&mut self, token_id: Vec<E::BaseField>) -> &mut Self {
        todo!()
    }
    pub fn add_token_salts(&mut self, salts: Vec<E::BaseField>) -> &mut Self {
        todo!()
    }
    pub fn add_recipients(&mut self, recipients: Vec<PublicKey<E>>) -> &mut Self {
        todo!()
    }
}

#[derive(Default)]
pub struct Commitment<F: PrimeField>(pub F);

impl<F: PrimeField> From<F> for Commitment<F> {
    fn from(value: F) -> Self {
        Commitment(value)
    }
}

#[derive(Default)]
pub struct Nullifier<F: PrimeField>(pub F);

pub struct Preimage<EmbedCurve: Pairing> {
    pub(crate) value: EmbedCurve::BaseField,
    pub(crate) token_id: EmbedCurve::BaseField,
    pub(crate) public_key: PublicKey<EmbedCurve>,
    pub(crate) salt: EmbedCurve::BaseField,
}

impl<EmbedCurve: Pairing> Preimage<EmbedCurve> {
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
    pub fn get_value(&self) -> EmbedCurve::BaseField {
        self.value
    }
    pub fn get_token_id(&self) -> EmbedCurve::BaseField {
        self.token_id
    }
    pub fn get_public_key(&self) -> PublicKey<EmbedCurve> {
        self.public_key.clone()
    }
    pub fn get_salt(&self) -> EmbedCurve::BaseField {
        self.salt
    }
}

pub struct Transaction<P: Pairing> {
    pub(crate) commitments: Vec<Commitment<P::ScalarField>>,
    pub(crate) nullifiers: Vec<Nullifier<P::ScalarField>>,
    pub(crate) proof: Proof<P>,
}

impl<P: Pairing> Transaction<P> {
    pub fn new(
        commitments: Vec<Commitment<P::ScalarField>>,
        nullifiers: Vec<Nullifier<P::ScalarField>>,
        proof: Proof<P>,
    ) -> Self {
        Self {
            commitments,
            nullifiers,
            proof,
        }
    }
}
