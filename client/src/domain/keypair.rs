use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::Group;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derivative::Derivative;

/// This defines a private-public keypair.

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize, Default, Debug)]
#[derivative(
    Copy(bound = "P: SWCurveConfig"),
    Clone(bound = "P: SWCurveConfig"),
    PartialEq(bound = "P: SWCurveConfig"),
    Eq(bound = "P: SWCurveConfig"),
    Hash(bound = "P: SWCurveConfig")
)]
pub struct PublicKey<P: SWCurveConfig>(pub Affine<P>);
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct PrivateKey<E: SWCurveConfig>(E::ScalarField);

impl<E: SWCurveConfig> PublicKey<E> {
    pub fn from_private_key(private_key: &PrivateKey<E>) -> Self {
        Self((E::GENERATOR * private_key.0).into())
    }

    pub fn as_affine(&self) -> Affine<E> {
        self.0
    }
}

impl<E: SWCurveConfig> PrivateKey<E> {
    pub fn from_scalar(scalar: E::ScalarField) -> Self {
        Self(scalar)
    }

    pub fn as_scalar(&self) -> E::ScalarField {
        self.0
    }
}
