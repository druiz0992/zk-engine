use ark_ec::CurveGroup;

pub trait SpendingKey<C: CurveGroup> {
    fn get_nullifier_key(&self) -> C::ScalarField;
}

pub trait OwnershipKey<C: CurveGroup> {
    fn get_ownership_key(&self) -> C::ScalarField;
}

pub trait FullKey<C: CurveGroup>: SpendingKey<C> + OwnershipKey<C> {
    fn get_private_key(&self) -> C::ScalarField;
}
