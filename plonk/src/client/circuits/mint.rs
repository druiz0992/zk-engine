use ark_ec::{
    pairing::Pairing,
    twisted_edwards::{Affine as TEAffine, TECurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};

use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonParams, PoseidonStateVar};
// private_value: ScalarField
// private_token_id: ScalarField
// private_token_nonce: ScalarField
// private_token_owner: ScalarField
// commitments: Vec<ScalarField>
// nullifiers: Vec<ScalarField>
// secrets: Vec<ScalarField>
pub fn mint_circuit<E, P, const C: usize>(
    value: [P::ScalarField; C],
    token_id: [P::ScalarField; C],
    token_nonce: [P::ScalarField; C],
    token_owner: TEAffine<E>,
) -> Result<PlonkCircuit<P::ScalarField>, CircuitError>
where
    E: TECurveConfig,
    P: Pairing<ScalarField = E::BaseField>,
    <E as CurveConfig>::BaseField: PrimeField + PoseidonParams,
{
    // Calculate output hash of the commitment
    let mut circuit = PlonkCircuit::new_turbo_plonk();
    for i in 0..C {
        let commitment_preimage_var = vec![
            value[i],
            token_id[i],
            token_nonce[i],
            token_owner.x,
            token_owner.y,
        ]
        .iter()
        .map(|&v| circuit.create_variable(v))
        .collect::<Result<Vec<_>, _>>()?;
        let commitment_var = PoseidonGadget::<PoseidonStateVar<6>, P::ScalarField>::hash(
            &mut circuit,
            commitment_preimage_var.as_slice(),
        )?;
        let commitment = circuit.witness(commitment_var)?;
        circuit.create_public_variable(commitment)?;
    }
    Ok(circuit)
}

#[cfg(test)]
mod test {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed_on_bn254::{EdwardsAffine, Fq, Fr};
    use jf_plonk::{
        proof_system::{PlonkKzgSnark, UniversalSNARK},
        transcript::StandardTranscript,
    };
    use jf_relation::{errors::CircuitError, Arithmetization, Circuit};
    use jf_utils::test_rng;
    use poseidon_ark::Poseidon;
    use std::str::FromStr;
    #[test]
    fn mint_test() -> Result<(), CircuitError> {
        let value = Fq::from_str("1").unwrap();
        let token_id = Fq::from_str("2").unwrap();
        let token_nonce = Fq::from_str("3").unwrap();
        let token_owner = (EdwardsAffine::generator() * Fr::from_str("4").unwrap()).into_affine();
        let mut circuit = super::mint_circuit::<ark_ed_on_bn254::EdwardsConfig, ark_bn254::Bn254, 1>(
            [value],
            [token_id],
            [token_nonce],
            token_owner,
        )?;
        let poseidon = Poseidon::new();
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
            .check_circuit_satisfiability(&[public_commitment])
            .is_ok());

        circuit.finalize_for_arithmetization()?;

        let mut rng = test_rng();

        let srs_size = circuit.srs_size()?;
        let srs =
            <PlonkKzgSnark<ark_bn254::Bn254> as UniversalSNARK<ark_bn254::Bn254>>::universal_setup_for_testing(
                srs_size, &mut rng,
            )?;

        let (pk, vk) = PlonkKzgSnark::<ark_bn254::Bn254>::preprocess(&srs, &circuit)?;

        let proof = PlonkKzgSnark::<ark_bn254::Bn254>::prove::<_, _, StandardTranscript>(
            &mut rng, &circuit, &pk, None,
        )?;

        let public_inputs = circuit.public_input()?;
        assert_eq!(public_inputs[0], public_commitment);

        assert!(
            PlonkKzgSnark::<ark_bn254::Bn254>::verify::<StandardTranscript>(
                &vk,
                &public_inputs,
                &proof,
                None,
            )
            .is_ok()
        );

        Ok(())
    }
}
