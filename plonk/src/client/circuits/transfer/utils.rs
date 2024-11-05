use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{PrimeField, UniformRand};

use jf_primitives::rescue::RescueParameter;
use jf_relation::errors::CircuitError;
use jf_relation::gadgets::ecc::SWToTEConParam;

use rand::SeedableRng;
use rand_chacha::ChaChaRng;

use super::check_inputs;
use super::constants::*;
use crate::client::circuits::circuit_inputs::CircuitInputs;
use crate::client::circuits::mint;
use crate::primitives::circuits::kem_dem::KemDemParams;
use crate::utils::poseidon_utils::build_commitment_hash;
use common::crypto::poseidon::constants::PoseidonParams;
use common::derived_keys::DerivedKeys;
use common::keypair::PublicKey;
use macros::client_circuit;
use trees::{AppendTree, MembershipPath, MembershipTree, Tree};

#[client_circuit]
pub fn build_random_inputs<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> Result<CircuitInputs<P>, CircuitError> {
    let mut rng = ChaChaRng::from_entropy();
    let mint_inputs = mint::utils::build_random_inputs::<P, V, _, N>()?;
    let mut mint_commitment_hashes = Vec::with_capacity(N);
    let mut total_value = V::ScalarField::from(ZERO);
    let mut indices = Vec::<V::ScalarField>::with_capacity(N);

    let root_key = V::ScalarField::rand(&mut rng);
    let derived_keys = DerivedKeys::<P>::new(root_key).map_err(CircuitError::ParameterError)?;
    let token_owner = derived_keys.public_key;

    let recipient_public_key = Affine::rand(&mut rng);

    for i in 0..N {
        let hash = build_commitment_hash([
            mint_inputs.token_values[i],
            mint_inputs.token_ids[i],
            mint_inputs.token_salts[i],
            token_owner.x,
            token_owner.y,
        ])
        .map_err(|_| {
            CircuitError::ParameterError(
                "Error generating hash commitment when building transfer inputs".to_string(),
            )
        })?;
        mint_commitment_hashes.push(hash);
        total_value += mint_inputs.token_values[i];
        indices.push(V::ScalarField::from(i as u64));
    }
    let commitment_tree = Tree::<V::ScalarField, D>::from_leaves(mint_commitment_hashes);
    let mut commitment_paths: Vec<MembershipPath<_>> = Vec::new();
    for j in 0..N {
        commitment_paths.push(commitment_tree.membership_witness(j).ok_or(
            CircuitError::ParameterError("Error computing membership witness".to_string()),
        )?);
    }

    let new_values =
        split_total_value::<_, C>(total_value).map_err(CircuitError::ParameterError)?;

    let circuit_inputs = CircuitInputs::new()
        .add_old_token_values(mint_inputs.token_values)
        .add_old_token_salts(mint_inputs.token_salts)
        .add_membership_path(commitment_paths)
        .add_membership_path_index(indices.clone())
        .add_commitment_tree_root(vec![commitment_tree.root(); N])
        .add_token_values(new_values)
        .add_token_salts(indices[0..C].to_vec())
        .add_token_ids(vec![mint_inputs.token_ids[0]; 1])
        .add_recipients(vec![PublicKey::from_affine(recipient_public_key)])
        .add_root_key(root_key)
        .add_ephemeral_key(V::ScalarField::rand(&mut rng))
        .build();
    check_inputs::<P, V, C, N, D>(&circuit_inputs)?;

    Ok(circuit_inputs)
}

fn split_total_value<F, const C: usize>(total: F) -> Result<Vec<F>, String>
where
    F: PrimeField,
{
    if C == 0 {
        return Err(
            "Incorrect number of output commitments when generating new transfer".to_string(),
        );
    }

    let mut value = vec![F::from(1_u64); C - 1];
    value.push(total - F::from((C - 1) as u64));

    Ok(value)
}
