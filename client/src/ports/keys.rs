use ark_ec::short_weierstrass::SWCurveConfig;

pub trait SpendingKey<C: SWCurveConfig> {
    fn get_nullifier_key(&self) -> C::BaseField;
}

pub trait OwnershipKey<C: SWCurveConfig> {
    fn get_ownership_key(&self) -> C::ScalarField;
}

pub trait FullKey<C: SWCurveConfig>: SpendingKey<C> + OwnershipKey<C> {
    fn get_private_key(&self) -> C::BaseField;
}
