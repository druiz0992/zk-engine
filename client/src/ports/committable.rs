use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr};
use ark_ff::PrimeField;
use common::crypto::{
    crypto_errors::CryptoError,
    poseidon::{constants::PoseidonParams, Poseidon},
};

use crate::domain::{Commitment, Preimage};

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
        match self.public_key.as_affine().xy() {
            Some((x, y)) => {
                let hash = poseidon.hash(vec![*x, *y])?;
                Ok(Commitment(hash))
            }
            None => Err(CryptoError::HashError("Error".to_string())),
        }
    }
}
