use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    AffineRepr, CurveGroup,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use poseidon_ark::Poseidon;

use crate::domain::{Commitment, Fr, Preimage};

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
    E: Pairing<BaseField = F, G1Affine = Affine<F>>,
    F: PrimeField + SWCurveConfig<BaseField = F>,
{
    type Error = String;

    fn commitment_hash(&self) -> Result<Commitment<F>, Self::Error> {
        let poseidon = Poseidon::new();
        match self.public_key.as_affine().xy() {
            Some((x, y)) => {
                // Hack to make this work for now, we need a generic Poseidon over F
                // and not just Fr.
                let hacky_poseidon_inputs: Vec<Fr> =
                    vec![self.value, self.token_id, self.salt, *x, *y]
                        .into_iter()
                        .map(|x| {
                            let big_int: BigUint = x.into_bigint().into();
                            Fr::from(big_int)
                        })
                        .collect();
                let hack_fr_hash = poseidon.hash(hacky_poseidon_inputs)?;
                let hash: BigUint = hack_fr_hash.into_bigint().into();
                Ok(Commitment(hash.into()))
            }
            None => Err("Error".to_string()),
        }
    }
}
