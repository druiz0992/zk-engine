use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveConfig};

use crate::domain::Preimage;

pub trait PreimageDB {
    type E: SWCurveConfig;

    fn get_value(&self, value: <Self::E as CurveConfig>::BaseField) -> Option<Preimage<Self::E>>;
    fn get_spendable(&self) -> Option<Vec<Preimage<Self::E>>>;
    fn get_all_preimages(&self) -> Vec<Preimage<Self::E>>;
    fn get_preimage(&self, key: <Self::E as CurveConfig>::ScalarField)
        -> Option<Preimage<Self::E>>;

    fn insert_preimage(
        &mut self,
        key: <Self::E as CurveConfig>::ScalarField,
        preimage: Preimage<Self::E>,
    ) -> Option<()>;
}
