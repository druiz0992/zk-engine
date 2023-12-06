use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, SWCurveConfig},
    CurveConfig,
};
use ark_ff::{PrimeField, Zero};
use common::crypto::poseidon::constants::PoseidonParams;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonStateVar};
// private_value: ScalarField
// private_token_id: ScalarField
// private_token_nonce: ScalarField
// private_token_owner: ScalarField
// commitments: Vec<ScalarField>
// nullifiers: Vec<ScalarField>
// secrets: Vec<ScalarField>
// C is the number of output commitments
pub fn mint_circuit<P, V, const C: usize>(
    value: [V::ScalarField; C],
    token_id: [V::ScalarField; C],
    token_nonce: [V::ScalarField; C],
    token_owner: [Affine<P>; C],
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
where
    P: SWCurveConfig,
    V: Pairing<ScalarField = P::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
{
    // Calculate output hash of the commitment
    let mut circuit = PlonkCircuit::new_turbo_plonk();
    // Swap_field = false
    circuit.create_public_boolean_variable(false)?;
    // We pretend N=1
    let commitment_root = V::ScalarField::zero();
    circuit.create_public_variable(commitment_root)?;
    let nullifier = V::ScalarField::zero();
    circuit.create_public_variable(nullifier)?;

    for i in 0..C {
        let commitment_preimage_var = vec![
            value[i],
            token_id[i],
            token_nonce[i],
            token_owner[i].x,
            token_owner[i].y,
        ]
        .iter()
        .map(|&v| circuit.create_variable(v))
        .collect::<Result<Vec<_>, _>>()?;
        let commitment_var = PoseidonGadget::<PoseidonStateVar<6>, V::ScalarField>::hash(
            &mut circuit,
            commitment_preimage_var.as_slice(),
        )?;
        circuit.set_variable_public(commitment_var)?;
    }
    let eph_pub_key = [V::ScalarField::zero(); 2];
    for e in eph_pub_key.iter() {
        circuit.create_public_variable(*e)?;
    }
    let ciphertexts = [V::ScalarField::zero(); 3];
    for c in ciphertexts.iter() {
        circuit.create_public_variable(*c)?;
    }
    Ok(circuit)
}

#[cfg(test)]
mod test {
    use ark_ec::short_weierstrass::SWCurveConfig;
    use ark_ec::CurveGroup;
    use common::crypto::poseidon::Poseidon;
    use curves::pallas::{Fq, Fr, PallasConfig};
    use curves::vesta::VestaConfig;
    use jf_relation::{errors::CircuitError, Circuit};
    use jf_utils::field_switching;
    use std::str::FromStr;
    #[test]
    fn mint_test() -> Result<(), CircuitError> {
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let secret_key = Fq::from_str("4").unwrap();
        let secret_key_fr = field_switching::<Fq, Fr>(&secret_key);
        let token_owner = (PallasConfig::GENERATOR * secret_key_fr).into_affine();
        let circuit = super::mint_circuit::<PallasConfig, VestaConfig, 1>(
            [value],
            [token_id],
            [token_nonce],
            [token_owner],
        )?;
        let poseidon: Poseidon<Fq> = Poseidon::new();
        let public_commitment = poseidon
            .hash(vec![
                value,
                token_id,
                token_nonce,
                token_owner.x,
                token_owner.y,
            ])
            .unwrap();

        assert!(circuit
            .check_circuit_satisfiability(&[
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                public_commitment,
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0),
                Fq::from(0)
            ])
            .is_ok());
        Ok(())
    }
}
