use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveConfig,
};
use ark_ff::PrimeField;

use jf_plonk::{
    nightfall::{
        ipa_structs::{ProvingKey, VerifyingKey},
        PlonkIpaSnark,
    },
    proof_system::UniversalSNARK,
};
use jf_primitives::rescue::RescueParameter;
use jf_relation::{errors::CircuitError, Circuit, PlonkCircuit};
use jf_relation::{gadgets::ecc::SWToTEConParam, Arithmetization};

use super::circuit_inputs::CircuitInputs;
use super::client_circuit::ClientCircuit;
use crate::client::ClientPlonkCircuit;
use crate::primitives::circuits::{
    kem_dem::{KemDemGadget, KemDemParams, PlainTextVars},
    merkle_tree::BinaryMerkleTreeGadget,
    poseidon::{PoseidonGadget, PoseidonStateVar},
};
use common::crypto::poseidon::{constants::PoseidonParams, Poseidon};
use common::{
    derived_keys::{DerivedKeys, NULLIFIER_PREFIX, PRIVATE_KEY_PREFIX},
    keypair::PublicKey,
};
use macros::client_circuit;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use std::str::FromStr;
use trees::MembershipPath;

// P: SWCurveConfig,
// <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,

// V: Pairing<ScalarField = P::BaseField>,
// V: Pairing<G1Affine = Affine<VSW>, G1 = Projective<VSW>, ScalarField = P::BaseField>,
// <V as Pairing>::BaseField: RescueParameter + SWToTEConParam,
// <V as Pairing>::ScalarField: KemDemParams<Field = <V as Pairing>::ScalarField>,

// VSW: SWCurveConfig<
// BaseField = <V as Pairing>::BaseField,
// ScalarField = <V as Pairing>::ScalarField,
// >,

const ZERO: u64 = 0;
const ONE: u64 = 1;
const PRIVATE_KEY_LEN: usize = 248;
const POSEIDON_STATE_VAR_LEN3: usize = 3;
const POSEIDON_STATE_VAR_LEN6: usize = 6;
const PLAINTEXT_VAR_LEN: usize = 3;

#[client_circuit]
pub struct TransferCircuit<P, V, VSW, const C: usize, const N: usize, const D: usize>(
    ClientCircuit<P, V, VSW, C, N, D>,
);

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize>
    TransferCircuit<P, V, VSW, C, N, D>
{
    pub fn new() -> Result<Self, CircuitError> {
        let circuit_inputs = build_default_inputs::<P, V, VSW, C, N, D>()?;
        let keys = generate_keys::<P, V, VSW, C, N, D>(circuit_inputs.clone())?;

        Ok(TransferCircuit(ClientCircuit::new(
            circuit_inputs,
            keys.0,
            keys.1,
        )))
    }

    pub fn set_inputs(&mut self, circuit_inputs: CircuitInputs<P, C, N, D>) {
        self.0.set_inputs(circuit_inputs);
    }

    pub fn get_inputs(&self) -> CircuitInputs<P, C, N, D> {
        self.0.circuit_inputs.clone()
    }

    pub fn get_proving_key(&self) -> ProvingKey<V> {
        self.0.proving_key.clone()
    }

    pub fn get_verifying_key(&self) -> VerifyingKey<V> {
        self.0.verifying_key.clone()
    }
}

#[client_circuit]
impl<P, V, VSW, const C: usize, const N: usize, const D: usize> ClientPlonkCircuit<P, V, C, N, D>
    for TransferCircuit<P, V, VSW, C, N, D>
{
    fn generate_keys(&self) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
        generate_keys::<P, V, VSW, C, N, D>(self.0.circuit_inputs.clone())
    }

    fn to_plonk_circuit(
        &self,
        circuit_inputs: CircuitInputs<P, C, N, D>,
    ) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
    where
        V: Pairing<ScalarField = P::BaseField>,
        P: SWCurveConfig,
        <P as CurveConfig>::BaseField: PrimeField + PoseidonParams<Field = V::ScalarField>,
    {
        transfer_circuit::<P, V, C, N, D>(circuit_inputs)
    }
}

#[client_circuit]
pub fn generate_keys<P, V, VSW, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: CircuitInputs<P, C, N, D>,
) -> Result<(ProvingKey<V>, VerifyingKey<V>), CircuitError> {
    let mut rng = ChaChaRng::from_entropy();
    let mut circuit = transfer_circuit::<P, V, C, N, D>(circuit_inputs)?;
    circuit.finalize_for_arithmetization()?;
    let srs_size = circuit.srs_size()?;
    let srs =
        <PlonkIpaSnark<V> as UniversalSNARK<V>>::universal_setup_for_testing(srs_size, &mut rng)?;
    let (pk, vk) = PlonkIpaSnark::<V>::preprocess(&srs, &circuit)?;
    Ok((pk, vk))
}

#[client_circuit]
fn build_default_inputs<P, V, VSW, const C: usize, const N: usize, const D: usize>(
) -> Result<CircuitInputs<P, C, N, D>, CircuitError> {
    let one = V::ScalarField::from(ONE);
    let zero = V::ScalarField::from(ZERO);
    let root_key = one;

    let derived_keys = DerivedKeys::new(root_key).map_err(CircuitError::FieldAlgebraError)?;
    let token_owner = derived_keys.public_key;

    let old_commitment_leaf_index = ZERO;

    let value = zero;
    let token_id = zero;
    let token_nonce = zero;
    let old_commitment_hash = Poseidon::<V::ScalarField>::new()
        .hash(vec![
            value,
            token_id,
            token_nonce,
            token_owner.x,
            token_owner.y,
        ])
        .unwrap();

    let mut old_commitment_sibling_path = MembershipPath::new();
    (0..D).for_each(|_| old_commitment_sibling_path.append(zero));

    let root = old_commitment_sibling_path
        .clone()
        .into_iter()
        .enumerate()
        .fold(old_commitment_hash, |a, (i, b)| {
            let poseidon: Poseidon<V::ScalarField> = Poseidon::new();
            let bit_dir = old_commitment_leaf_index >> i & 1;
            if bit_dir == 0 {
                poseidon.hash(vec![a, b]).unwrap()
            } else {
                poseidon.hash(vec![b, a]).unwrap()
            }
        });

    let ephemeral_key = zero;
    let mut circuit_inputs_builder = CircuitInputs::<P, C, N, D>::new();
    let circuit_inputs = circuit_inputs_builder
        .add_token_values(vec![value; C])
        .add_token_salts(vec![V::ScalarField::from(old_commitment_leaf_index); C]) //only the first salt needs to be the index
        .add_token_ids(vec![token_id])
        .add_old_token_values(vec![value; N])
        .add_old_token_salts(vec![token_nonce; N])
        .add_commitment_tree_root(vec![root; N])
        .add_membership_path(vec![old_commitment_sibling_path; N])
        .add_membership_path_index(vec![V::ScalarField::from(old_commitment_leaf_index); N])
        .add_recipients(vec![PublicKey::from_affine(token_owner)])
        .add_ephemeral_key(ephemeral_key)
        .add_root_key(root)
        .build()?;

    Ok(circuit_inputs)
}
// N: number of nullifiers
// C: number of commitments
// D: depth of the merkle tree
pub fn transfer_circuit<P, V, const C: usize, const N: usize, const D: usize>(
    circuit_inputs: CircuitInputs<P, C, N, D>,
) -> Result<PlonkCircuit<V::ScalarField>, CircuitError>
where
    P: SWCurveConfig,
    V: Pairing<ScalarField = P::BaseField>,
    <P as CurveConfig>::BaseField: PrimeField + KemDemParams<Field = V::ScalarField>,
{
    if circuit_inputs.recipients.len() != 1 {
        return Err(CircuitError::ParameterError(format!(
            "Incorrect length for recipients. Expected: 1, Obtained {}",
            circuit_inputs.recipients.len()
        )));
    }
    if circuit_inputs.token_ids.len() != 1 {
        return Err(CircuitError::ParameterError(format!(
            "Incorrect length for token_ids. Expected: 1 , Obtained {}",
            circuit_inputs.token_ids.len()
        )));
    }
    let mut circuit = PlonkCircuit::new_turbo_plonk();

    // Swap_field = false
    circuit.create_public_boolean_variable(false)?;

    let private_key_domain = P::BaseField::from_str(PRIVATE_KEY_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;
    let nullifier_key_domain = P::BaseField::from_str(NULLIFIER_PREFIX)
        .map_err(|_| CircuitError::NotSupported(String::from("Prefix")))?;
    // Derive Keys - ToDo, remove this once we have HSM-compatible key derivation
    let private_key_domain_var = circuit.create_constant_variable(private_key_domain)?;
    let nullifier_key_domain_var = circuit.create_constant_variable(nullifier_key_domain)?;
    let root_key_var = circuit.create_variable(circuit_inputs.root_key)?;

    let private_key_var = PoseidonGadget::<
        PoseidonStateVar<POSEIDON_STATE_VAR_LEN3>,
        V::ScalarField,
    >::hash(&mut circuit, &[root_key_var, private_key_domain_var])?;
    let private_key_bits_var =
        circuit.unpack(private_key_var, V::ScalarField::MODULUS_BIT_SIZE as usize)?;

    let private_key_var_trunc = private_key_bits_var
        .into_iter()
        .take(PRIVATE_KEY_LEN)
        .collect::<Vec<_>>();

    let private_key_var_trunc_bits = private_key_var_trunc.as_slice();
    let generator_point_var = &circuit.create_constant_sw_point_variable(P::GENERATOR.into())?;

    // Implicit mod being done here
    let public_key_var = circuit
        .variable_base_binary_sw_scalar_mul::<P>(private_key_var_trunc_bits, generator_point_var)?;

    let nullifier_key_var = PoseidonGadget::<
        PoseidonStateVar<POSEIDON_STATE_VAR_LEN3>,
        V::ScalarField,
    >::hash(&mut circuit, &[root_key_var, nullifier_key_domain_var])?;

    // Check conservation of value
    // That is, sum of nullifiers = sum of commitments
    let old_commitment_values_vars = circuit_inputs
        .old_token_values
        .iter()
        .map(|v| circuit.create_variable(*v))
        .collect::<Result<Vec<_>, _>>()?;
    let commitment_values_vars = circuit_inputs
        .token_values
        .iter()
        .map(|v| circuit.create_variable(*v))
        .collect::<Result<Vec<_>, _>>()?;

    let nullifiers_sum_var = old_commitment_values_vars
        .iter()
        .try_fold(circuit.zero(), |acc, v| circuit.add(acc, *v))?;

    let commitment_sum_var = commitment_values_vars
        .iter()
        .try_fold(circuit.zero(), |acc, v| circuit.add(acc, *v))?;

    circuit.enforce_equal(nullifiers_sum_var, commitment_sum_var)?;

    // Calculate the private old commitment hash and check the sibling path
    // Calculate the public nullifier hash
    let token_id_var = circuit.create_variable(circuit_inputs.token_ids[0])?;
    // TODO public input can be a hash of old roots, to be re-calc'd in base circuit
    let commitment_roots_vars = circuit_inputs
        .commitment_tree_root
        .iter()
        .map(|r| circuit.create_public_variable(*r).unwrap())
        .collect::<Vec<_>>();
    for (i, &old_commitment_val_var) in old_commitment_values_vars.iter().enumerate() {
        let old_commitment_nonce_var =
            circuit.create_variable(circuit_inputs.old_token_salts[i])?;
        let old_commitment_hash_var =
            PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
                &mut circuit,
                &[
                    old_commitment_val_var,
                    token_id_var,
                    old_commitment_nonce_var,
                    public_key_var.get_x(),
                    public_key_var.get_y(),
                ],
            )?;
        // Check the sibling path
        let commitment_root_var = commitment_roots_vars[i];
        let calc_commitment_root_var = BinaryMerkleTreeGadget::<D, V::ScalarField>::calculate_root(
            &mut circuit,
            old_commitment_hash_var,
            circuit_inputs.membership_path_index[i],
            circuit_inputs.membership_path[i]
                .clone()
                .try_into()
                .map_err(|_| {
                    CircuitError::ParameterError("Error converting membership path".to_string())
                })?,
        )?;
        circuit.enforce_equal(calc_commitment_root_var, commitment_root_var)?;

        let nullifier_hash_var = PoseidonGadget::<PoseidonStateVar<3>, V::ScalarField>::hash(
            &mut circuit,
            &[nullifier_key_var, old_commitment_hash_var],
        )?;
        circuit.set_variable_public(nullifier_hash_var)?;
    }

    // Calculate the recipients(first) commitment hash, this has an additional requirement
    // Check that the first commitment nonce is the same as the index of the first commitment
    // Check that the recipients public key is set as the new owner
    let recipient_commitment_nonce_var = circuit.create_variable(circuit_inputs.token_salts[0])?;
    let index_of_first_commitment_var =
        circuit.create_variable(circuit_inputs.membership_path_index[0])?;
    circuit.enforce_equal(
        recipient_commitment_nonce_var,
        index_of_first_commitment_var,
    )?;

    let recipient_var =
        circuit.create_sw_point_variable(circuit_inputs.recipients[0].as_affine().into())?;
    let recipient_commitment_hash_var =
        PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
            &mut circuit,
            &[
                commitment_values_vars[0],
                token_id_var,
                recipient_commitment_nonce_var,
                recipient_var.get_x(),
                recipient_var.get_y(),
            ],
        )?;
    circuit.set_variable_public(recipient_commitment_hash_var)?;

    // Calculate the remaining change commitment hashes ()
    // The recipients of these commitments are the same as the sender
    // TODO set to one (and => C < 3 always) as no reason to send yourself multiple change commitments
    // TODO don't provide the change commit value, calc it in circuit
    for i in 1..C {
        let commitment_nonce_var = circuit.create_variable(circuit_inputs.token_salts[i])?;
        let commitment_hash_var =
            PoseidonGadget::<PoseidonStateVar<POSEIDON_STATE_VAR_LEN6>, V::ScalarField>::hash(
                &mut circuit,
                &[
                    commitment_values_vars[i],
                    token_id_var,
                    commitment_nonce_var,
                    public_key_var.get_x(),
                    public_key_var.get_y(),
                ],
            )?;
        circuit.set_variable_public(commitment_hash_var)?;
    }

    // Check the encryption of secret information to the recipient
    // This proves that they will be able to decrypt the information
    let gen = circuit.create_constant_sw_point_variable(P::GENERATOR.into())?;
    let ephemeral_key_var = circuit.create_variable(circuit_inputs.ephemeral_key)?;
    let eph_key_bits =
        circuit.unpack(ephemeral_key_var, P::BaseField::MODULUS_BIT_SIZE as usize)?;
    let eph_public_key = circuit.variable_base_binary_sw_scalar_mul::<P>(&eph_key_bits, &gen)?;
    circuit.set_variable_public(eph_public_key.get_x())?;
    circuit.set_variable_public(eph_public_key.get_y())?;

    let ciphertext_vars =
        KemDemGadget::<PlainTextVars<PLAINTEXT_VAR_LEN>, P, V::ScalarField>::kem_dem(
            &mut circuit,
            ephemeral_key_var,
            recipient_var,
            [
                commitment_values_vars[0],
                token_id_var,
                recipient_commitment_nonce_var,
            ],
        )?;
    for ciphertext in ciphertext_vars {
        circuit.set_variable_public(ciphertext)?;
    }

    Ok(circuit)
}

#[cfg(test)]
mod test {
    use super::CircuitInputs;
    use ark_std::UniformRand;
    use common::crypto::poseidon::Poseidon;
    use common::derived_keys::DerivedKeys;
    use common::keypair::PublicKey;
    use curves::{
        pallas::{Fq, PallasConfig},
        vesta::VestaConfig,
    };
    use jf_relation::{errors::CircuitError, Circuit};
    use jf_utils::test_rng;
    use std::str::FromStr;
    use trees::{
        membership_tree::{MembershipTree, Tree},
        tree::AppendTree,
        MembershipPath,
    };

    #[test]
    fn transfer_test() -> Result<(), CircuitError> {
        transfer_test_helper::<1, 1, 8>()?;
        transfer_test_helper::<2, 2, 8>()?;
        transfer_test_helper::<2, 1, 8>()?;
        transfer_test_helper::<5, 2, 8>()
    }

    fn transfer_test_helper<const C: usize, const N: usize, const D: usize>(
    ) -> Result<(), CircuitError> {
        let root_key = Fq::rand(&mut test_rng());

        let derived_keys = DerivedKeys::new(root_key).map_err(CircuitError::FieldAlgebraError)?;
        let token_owner = derived_keys.public_key;

        let token_id = Fq::from_str("2").unwrap();

        let mut values = vec![];
        let mut token_nonces = vec![];
        let mut old_commitment_hashes = vec![];
        let mut total_value = Fq::from(0 as u32);

        for j in 0..N {
            let value = Fq::from(j as u32 + 10);
            let token_nonce = Fq::from(j as u32 + 3);
            let old_commitment_hash = Poseidon::<Fq>::new()
                .hash(vec![
                    value,
                    token_id,
                    token_nonce,
                    token_owner.x,
                    token_owner.y,
                ])
                .unwrap();
            values.push(value);
            token_nonces.push(token_nonce);
            old_commitment_hashes.push(old_commitment_hash);
            total_value += value;
        }

        let comm_tree: Tree<Fq, 8> = Tree::from_leaves(old_commitment_hashes);
        let mut old_comm_paths: Vec<MembershipPath<_>> = Vec::new();
        for j in 0..N {
            old_comm_paths.push(comm_tree.membership_witness(j).unwrap());
        }

        let mut new_values = [Fq::from(0 as u32); C];
        if C > 1 {
            new_values[0] = total_value - Fq::from(1 as u32);
            new_values[1] = Fq::from(1 as u32);
        } else {
            new_values[0] = total_value;
        }

        let circuit_inputs = CircuitInputs::<PallasConfig, C, N, D>::new()
            .add_old_token_values(values)
            .add_old_token_salts(token_nonces)
            .add_membership_path(old_comm_paths)
            .add_membership_path_index(
                ark_std::array::from_fn::<_, N, _>(|i| Fq::from(i as u32)).to_vec(),
            )
            .add_commitment_tree_root(vec![comm_tree.root(); N])
            .add_token_values(new_values.to_vec())
            .add_token_salts(ark_std::array::from_fn::<_, C, _>(|i| Fq::from(i as u32)).to_vec())
            .add_token_ids(vec![token_id])
            .add_recipients(vec![PublicKey::from_affine(token_owner)])
            .add_root_key(root_key)
            .add_ephemeral_key(Fq::rand(&mut test_rng()))
            .build()?;

        let circuit =
            super::transfer_circuit::<PallasConfig, VestaConfig, C, N, D>(circuit_inputs)?;

        let public_inputs = circuit.public_input()?;
        assert!(circuit.check_circuit_satisfiability(&public_inputs).is_ok());
        Ok(())
    }
}
