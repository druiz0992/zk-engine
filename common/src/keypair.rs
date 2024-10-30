use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
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

    pub fn from_affine(public_key: Affine<E>) -> Self {
        Self(public_key)
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

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::CurveGroup;
    use ark_ff::UniformRand;
    use curves::pallas::{Fr, PallasConfig};
    use jf_utils::test_rng;

    #[test]
    fn test_private_key_from_scalar() {
        let scalar = Fr::rand(&mut test_rng());

        let private_key = PrivateKey::<PallasConfig>::from_scalar(scalar);
        assert_eq!(
            private_key.as_scalar(),
            scalar,
            "Private key scalar mismatch"
        );
    }

    #[test]
    fn test_public_key_from_private_key() {
        let scalar = Fr::rand(&mut test_rng());

        let private_key = PrivateKey::<PallasConfig>::from_scalar(scalar);
        let public_key = PublicKey::<PallasConfig>::from_private_key(&private_key);

        let expected_public_key_affine = (PallasConfig::GENERATOR * scalar).into_affine();
        assert_eq!(
            public_key.as_affine(),
            expected_public_key_affine,
            "Public key generation mismatch"
        );
    }

    #[test]
    fn test_public_key_as_affine() {
        let scalar = Fr::rand(&mut test_rng());

        let private_key = PrivateKey::<PallasConfig>::from_scalar(scalar);
        let public_key = PublicKey::<PallasConfig>::from_private_key(&private_key);

        let affine_rep = public_key.as_affine();
        assert_eq!(
            affine_rep,
            (PallasConfig::GENERATOR * scalar).into_affine(),
            "Affine representation mismatch"
        );
    }

    #[test]
    fn test_public_key_from_affine() {
        let scalar = Fr::rand(&mut test_rng());

        let expected_affine = (PallasConfig::GENERATOR * scalar).into_affine();
        let public_key = PublicKey::<PallasConfig>::from_affine(expected_affine);

        assert_eq!(
            public_key.as_affine(),
            expected_affine,
            "Public key from affine mismatch"
        );
    }
}
