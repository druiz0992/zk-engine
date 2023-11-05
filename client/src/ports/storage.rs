use ark_ec::pairing::Pairing;

use crate::domain::Preimage;

pub trait PreimageDB<E: Pairing> {
    type K;
    fn get_value(&self, value: E::BaseField) -> Option<Preimage<E>>;
    fn get_spendable(&self) -> Option<Vec<Preimage<E>>>;
    fn get_preimage(&self, key: Self::K) -> Option<Preimage<E>>;

    fn insert_preimage(&mut self, key: Self::K, preimage: Preimage<E>) -> Option<()>;
}
