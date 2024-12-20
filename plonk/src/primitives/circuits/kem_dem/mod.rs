mod kem_dem_constants;

use ark_ec::short_weierstrass::SWCurveConfig;

use ark_ff::{PrimeField, Zero};
use common::crypto::poseidon::constants::PoseidonParams;
use jf_relation::{
    errors::CircuitError, gadgets::ecc::short_weierstrass::SWPointVariable, Circuit, PlonkCircuit,
    Variable,
};

use crate::primitives::circuits::poseidon::{PoseidonGadget, PoseidonStateVar};
// from_le_bytes_mod_order(
pub trait KemDemParams: PoseidonParams {
    const DOMAIN_DEM: &'static [u8; kem_dem_constants::FIELD_ELEMENT_BYTES];
    const DOMAIN_KEM: &'static [u8; kem_dem_constants::FIELD_ELEMENT_BYTES];
}

pub trait KemDemGadget<T, E, F> {
    fn kem(
        &mut self,
        ephemeral_key: Variable,
        recipient: SWPointVariable,
    ) -> Result<Variable, CircuitError>;
    fn dem(&mut self, encryption_key: Variable, plaintext: T) -> Result<T, CircuitError>;
    fn kem_dem(
        &mut self,
        ephemeral_key: Variable,
        recipient: SWPointVariable,
        plaintext: T,
    ) -> Result<T, CircuitError>;
}

pub type PlainTextVars<const N: usize> = [Variable; N];
impl<E, F, const N: usize> KemDemGadget<PlainTextVars<N>, E, F> for PlonkCircuit<F>
where
    E: SWCurveConfig<BaseField = F>,
    F: PrimeField + KemDemParams<Field = F>,
{
    fn kem(
        &mut self,
        ephemeral_key_var: Variable,
        recipient_var: SWPointVariable,
    ) -> Result<Variable, CircuitError> {
        let domain_kem = F::from_le_bytes_mod_order(F::DOMAIN_KEM);
        let domain_kem_var = self.create_constant_variable(domain_kem)?;
        let ephemeral_key_var_bits =
            self.unpack(ephemeral_key_var, F::MODULUS_BIT_SIZE as usize)?;
        // This needs to be public
        let shared_secret_var =
            self.variable_base_binary_sw_scalar_mul::<E>(&ephemeral_key_var_bits, &recipient_var)?;
        let encryption_key = PoseidonGadget::<PoseidonStateVar<4>, F>::hash(
            self,
            &[
                shared_secret_var.get_x(),
                shared_secret_var.get_y(),
                domain_kem_var,
            ],
        )?;

        Ok(encryption_key)
    }

    fn dem(
        &mut self,
        encryption_key_var: Variable,
        plaintext_vars: PlainTextVars<N>,
    ) -> Result<[Variable; N], CircuitError> {
        let domain_dem = F::from_le_bytes_mod_order(F::DOMAIN_DEM);
        let domain_dem_var = self.create_constant_variable(domain_dem)?;
        let mut ciphertext_vars = [Variable::zero(); N];

        for i in 0..N {
            let i_var = self.create_constant_variable(F::from(i as u32))?;
            let hash = PoseidonGadget::<PoseidonStateVar<4>, F>::hash(
                self,
                &[encryption_key_var, domain_dem_var, i_var],
            )?;
            ciphertext_vars[i] = self.add(hash, plaintext_vars[i])?;
        }

        Ok(ciphertext_vars)
    }

    fn kem_dem(
        &mut self,
        ephemeral_key: Variable,
        recipient: SWPointVariable,
        plaintext: PlainTextVars<N>,
    ) -> Result<[Variable; N], CircuitError> {
        let encryption_key: Variable =
            KemDemGadget::<PlainTextVars<N>, E, F>::kem(self, ephemeral_key, recipient)?;
        KemDemGadget::<PlainTextVars<N>, E, F>::dem(self, encryption_key, plaintext)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ark_ec::CurveGroup;
    use ark_std::UniformRand;
    use common::crypto::poseidon::Poseidon;
    use curves::pallas::{Affine, Fq, Fr, PallasConfig};
    use jf_utils::field_switching;

    #[test]
    fn test_kem_dem_gadget() {
        test_kem_dem_gadget_helper();
    }

    fn dem<F: KemDemParams>(enc_key: Fq, plain_texts: Vec<Fq>) -> Vec<Fq> {
        let domain_dem = Fq::from_le_bytes_mod_order(F::DOMAIN_DEM);
        let mut ciphertexts = Vec::new();
        for (i, plain_text) in plain_texts.iter().enumerate() {
            let poseidon: Poseidon<Fq> = Poseidon::new();
            let hash = poseidon
                .hash(vec![enc_key, domain_dem, Fq::from(i as u32)])
                .unwrap();
            ciphertexts.push(hash + plain_text);
        }
        ciphertexts
    }

    fn undo_dem<F: KemDemParams>(enc_key: Fq, cipher_texts: Vec<Fq>) -> Vec<Fq> {
        let domain_dem = Fq::from_le_bytes_mod_order(F::DOMAIN_DEM);
        let mut plain_texts = Vec::new();
        for (i, cipher_text) in cipher_texts.iter().enumerate() {
            let hash = Poseidon::<Fq>::new()
                .hash(vec![enc_key, domain_dem, Fq::from(i as u32)])
                .unwrap();
            plain_texts.push(cipher_text - &hash);
        }
        plain_texts
    }

    fn kem<F: KemDemParams>(private_key: Fr, recipient: Affine) -> Fq {
        let domain_kem = Fq::from_le_bytes_mod_order(F::DOMAIN_KEM);
        let shared_secret = (recipient * private_key).into_affine();
        Poseidon::<Fq>::new()
            .hash(vec![shared_secret.x, shared_secret.y, domain_kem])
            .unwrap()
    }

    fn encrypt<F: KemDemParams>(
        ephemeral_key: Fr,
        recipient: Affine,
        plain_texts: Vec<Fq>,
    ) -> Vec<Fq> {
        let enc_key = kem::<F>(ephemeral_key, recipient);
        dem::<F>(enc_key, plain_texts)
    }

    fn decrypt<F: KemDemParams>(
        recipient_private_key: Fr,
        ephemeral_pub: Affine,
        cipher_texts: Vec<Fq>,
    ) -> Vec<Fq> {
        let enc_key = kem::<F>(recipient_private_key, ephemeral_pub);
        undo_dem::<F>(enc_key, cipher_texts)
    }

    fn test_kem_dem_gadget_helper() {
        let mut rng = ark_std::test_rng();
        let rand_plaintexts = (0..3).map(|_| Fq::rand(&mut rng)).collect::<Vec<_>>();
        let ephemeral_key = Fq::rand(&mut rng);
        let ephemeral_key_fr = field_switching::<Fq, Fr>(&ephemeral_key);
        let ephemeral_pub = PallasConfig::GENERATOR * ephemeral_key_fr;

        let recipient_private_key = Fq::rand(&mut rng);
        let recipient_private_key_fr = field_switching::<Fq, Fr>(&recipient_private_key);
        let recipient = PallasConfig::GENERATOR * recipient_private_key_fr;

        let mut circuit = PlonkCircuit::<Fq>::new_turbo_plonk();

        let recipient_var = circuit.create_sw_point_variable(recipient.into()).unwrap();
        let plain_text_vars: PlainTextVars<3> = rand_plaintexts
            .iter()
            .map(|&b| circuit.create_variable(b).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let ephemeral_key_var = circuit.create_variable(ephemeral_key).unwrap();

        let expected_ciphertexts =
            encrypt::<Fq>(ephemeral_key_fr, recipient.into(), rand_plaintexts.clone());
        let decrypted_plaintexts = decrypt::<Fq>(
            recipient_private_key_fr,
            ephemeral_pub.into(),
            expected_ciphertexts.clone(),
        );

        let circuit_results = KemDemGadget::<PlainTextVars<3>, PallasConfig, Fq>::kem_dem(
            &mut circuit,
            ephemeral_key_var,
            recipient_var,
            plain_text_vars,
        )
        .unwrap();
        let circuit_ciphertext = circuit_results
            .into_iter()
            .map(|v| circuit.witness(v).unwrap().to_string())
            .collect::<Vec<_>>();

        let expected_ciphertext_strs = expected_ciphertexts
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>();
        assert!(expected_ciphertext_strs.eq(&circuit_ciphertext));
        assert!(decrypted_plaintexts.eq(&rand_plaintexts));
    }
}
