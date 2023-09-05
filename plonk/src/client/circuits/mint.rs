use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    AffineRepr, CurveConfig, CurveGroup,
};
use jf_relation::PlonkCircuit;

use jf_plonk::errors::PlonkError;
// private_value: ScalarField
// private_token_id: ScalarField
// private_token_nonce: ScalarField
// private_token_owner: ScalarField
// commitments: Vec<ScalarField>
// nullifiers: Vec<ScalarField>
// secrets: Vec<ScalarField>
pub fn mint_circuit<E, P>(
    value: P::ScalarField,
    token_id: P::ScalarField,
    token_nonce: P::ScalarField,
    token_owner: TEAffine<E>,
) -> Result<PlonkCircuit<P::ScalarField>, PlonkError>
where
    E: TECurveConfig,
    P: Pairing,
{
    // Calculate output hash of the commitment
    poseidon_hasher.hash(&[value, token_id, token_nonce, token_owner.x, token_owner.y])
}
