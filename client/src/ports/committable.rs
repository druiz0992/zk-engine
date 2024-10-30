use ark_ec::short_weierstrass::SWCurveConfig;
use ark_ff::PrimeField;
use common::{
    crypto::{
        crypto_errors::CryptoError,
        poseidon::{constants::PoseidonParams, Poseidon},
    },
    structs::Commitment,
};

use crate::domain::Preimage;

pub trait Committable<F: PrimeField> {
    type Error;

    fn commitment_hash(&self) -> Result<Commitment<F>, Self::Error>;
}

pub trait Nullifiable<F: PrimeField>: Committable<F> {
    fn nullifier_hash<Hasher>(&self) -> Result<F, Self::Error>;
}

// Implementation of how a Preimage can be committed to.
impl<E, F> Committable<F> for Preimage<E>
where
    E: SWCurveConfig<BaseField = F>,
    F: PrimeField + PoseidonParams<Field = F>,
{
    type Error = CryptoError;

    fn commitment_hash(&self) -> Result<Commitment<F>, Self::Error> {
        let poseidon = Poseidon::<F>::new();
        if let Some(elements) = self.to_vec() {
            let hash = poseidon.hash(elements)?;
            Ok(Commitment(hash))
        } else {
            Err(CryptoError::HashError("Error".to_string()))
        }
    }
}
