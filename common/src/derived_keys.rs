use crate::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use ark_ec::{
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig, CurveGroup,
};
use ark_ff::PrimeField;
use num_bigint::BigUint;
use std::str::FromStr;

/// Prefix for hashes for zkp private ket and nullifier
/// PRIVATE_KEY_PREFIX = keccak256('zkpPrivateKey'), need to update for Pasta
pub const PRIVATE_KEY_PREFIX: &str =
    "2708019456231621178814538244712057499818649907582893776052749473028258908910";
/// PRIVATE_KEY_PREFIX = keccak256('nullifierKey'), need to update for Pasta
pub const NULLIFIER_PREFIX: &str =
    "7805187439118198468809896822299973897593108379494079213870562208229492109015";

pub struct DerivedKeys<P: SWCurveConfig> {
    pub private_key: P::ScalarField,
    pub nullifier_key: P::BaseField,
    pub public_key: Affine<P>,
}

impl<P> DerivedKeys<P>
where
    P: SWCurveConfig,
    <P as CurveConfig>::BaseField:
        PoseidonParams<Field = <P as CurveConfig>::BaseField> + PrimeField,
{
    const PRIVATE_KEY_LEN: usize = 31;

    pub fn new(root_key: <P as CurveConfig>::BaseField) -> Result<Self, String> {
        let poseidon = Poseidon::<P::BaseField>::new();

        let pk_prefix = P::BaseField::from_str(PRIVATE_KEY_PREFIX)
            .map_err(|_| "Error converting Private Key Prefix".to_string())?;
        let private_key = poseidon.hash_unchecked(vec![root_key, pk_prefix]);
        let private_key_bn: BigUint = private_key.into();
        let mut private_key_bytes = private_key_bn.to_bytes_le();
        private_key_bytes.truncate(DerivedKeys::<P>::PRIVATE_KEY_LEN);
        let private_key_trunc = P::ScalarField::from_le_bytes_mod_order(&private_key_bytes);

        let nullifier_prefix = P::BaseField::from_str(NULLIFIER_PREFIX)
            .map_err(|_| "Error converting Nullifier Prefix".to_string())?;
        let nullifier_key = poseidon.hash_unchecked(vec![root_key, nullifier_prefix]);
        let public_key = (P::GENERATOR * private_key_trunc).into_affine();

        Ok(DerivedKeys {
            private_key: private_key_trunc,
            nullifier_key,
            public_key,
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use ark_ff::UniformRand;
    use curves::pallas::{Fq, PallasConfig};

    use jf_utils::test_rng;

    #[test]
    fn test_generate_validkeys() {
        for _i in 0..100 {
            let root_key = Fq::rand(&mut test_rng());
            DerivedKeys::<PallasConfig>::new(root_key).expect("Derived keys couldnt be computed");
        }
    }
}
