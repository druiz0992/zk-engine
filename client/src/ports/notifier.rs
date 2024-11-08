use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use async_trait::async_trait;
use common::structs::Transaction;

#[async_trait]
pub trait Notifier<P: Pairing>: Clone + Send + Sync + 'static
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    async fn send_transaction(&self, transaction: Transaction<P>) -> anyhow::Result<()>;
}
