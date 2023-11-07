use ark_ec::Group;
use ark_ec::{pairing::Pairing, CurveGroup};

/// This defines a private-public keypair.

#[derive(Clone)]
pub struct PublicKey<E: Pairing>(E::G1Affine);
pub struct PrivateKey<E: Pairing>(E::ScalarField);

impl<E: Pairing> PublicKey<E> {
    pub fn from_private_key(private_key: &PrivateKey<E>) -> Self {
        Self((E::G1::generator() * private_key.0).into())
    }

    pub fn as_affine(&self) -> E::G1Affine {
        self.0
    }
}

impl<E: Pairing> PrivateKey<E> {
    pub fn from_scalar(scalar: E::ScalarField) -> Self {
        Self(scalar)
    }

    pub fn as_scalar(&self) -> E::ScalarField {
        self.0
    }
}
