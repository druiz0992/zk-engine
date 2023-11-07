use crate::{domain::Commitment, ports::committable::Committable};
use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use poseidon_ark::Poseidon;

use crate::{
    domain::{CircuitInputs, CircuitType::Mint, Preimage, Proof, PublicKey, Transaction},
    ports::prover::Prover,
};

pub fn mint_tokens<E, I, P, F>(
    token_values: Vec<E::ScalarField>,
    token_ids: Vec<E::ScalarField>,
    salts: Vec<E::ScalarField>,
    owners: Vec<PublicKey<I>>,
) -> Result<Transaction<E>, &'static str>
where
    F: PrimeField + SWCurveConfig<BaseField = F>,
    E: Pairing<ScalarField = F>,
    I: Pairing<BaseField = F, G1Affine = Affine<F>>,
    P: Prover<E>,
{
    let mut circuit_inputs_builder = CircuitInputs::<I>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_ids(token_ids)
        .add_token_salts(salts)
        .add_token_values(token_values)
        .add_recipients(owners)
        .build();
    let poseidon = Poseidon::new();
    // let commitments: Vec<Commitment<F>> = token_values
    //     .iter()
    //     .enumerate()
    //     .map(|(i, &v)| {
    //         let preimage: Preimage<I> = Preimage::new(v, token_ids[i], owners[i], salts[i]);
    //         preimage.commitment_hash()
    //     })
    //     .collect::<Result<Vec<_>, String>>()
    //     .map_err(|e| &*e)?;

    let (proof, pub_inputs): (Proof<E>, Vec<E::ScalarField>) = P::prove(Mint, circuit_inputs)?;
    let commitments = pub_inputs.into_iter().map(|x| x.into()).collect();

    let transaction = Transaction::new(commitments, Default::default(), proof);
    Ok(transaction)
}
