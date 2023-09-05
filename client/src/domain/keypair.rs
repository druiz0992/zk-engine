use ark_ec::CurveGroup;

/// This defines a private-public keypair.

pub struct PublicKey<E: CurveGroup>(E::Affine);
pub struct PrivateKey<E: CurveGroup>(E::ScalarField);

impl<E: CurveGroup> PublicKey<E> {
    pub fn from_private_key(private_key: &PrivateKey<E>) -> Self {
        Self((E::generator() * private_key.0).into())
    }

    pub fn as_affine(&self) -> E::Affine {
        self.0
    }
}

impl<E: CurveGroup> PrivateKey<E> {
    pub fn from_scalar(scalar: E::ScalarField) -> Self {
        Self(scalar)
    }

    pub fn as_scalar(&self) -> E::ScalarField {
        self.0
    }
}
