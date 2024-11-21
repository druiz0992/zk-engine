use std::marker::PhantomData;

use crate::structs::Block;
use crate::structs::Transaction;
use crate::{configuration::ApplicationSettings, ports::notifier::Notifier};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use ark_ff::Field;
use async_trait::async_trait;

#[derive(Clone, Debug)]
pub struct HttpNotifier<V> {
    pub base_url: String,
    _marker: std::marker::PhantomData<V>,
}

impl<V> HttpNotifier<V> {
    pub fn new(settings: ApplicationSettings) -> Self {
        let _timeout = settings.timeout();
        Self {
            base_url: settings.base_url,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<V> Notifier for HttpNotifier<Transaction<V>>
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
    Transaction<V>: Send + Sync,
{
    type Info = Transaction<V>;

    #[tracing::instrument(name = "Send notification", skip(transaction))]
    async fn send_info(&self, transaction: Transaction<V>) -> anyhow::Result<()> {
        let base_url = self.base_url.clone();
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/transactions", base_url))
            .json(&transaction)
            .send()
            .await;
        ark_std::println!("Got response {:?} from {}", res, base_url);
        Ok(())
    }
}

#[async_trait]
impl<F> Notifier for HttpNotifier<Block<F>>
where
    F: Field,
{
    type Info = Block<F>;

    #[tracing::instrument(name = "Send notification", skip(block))]
    async fn send_info(&self, block: Block<F>) -> anyhow::Result<()> {
        let base_url = self.base_url.clone();
        let client = reqwest::Client::new();
        let res = client
            .post(format!("{}/transactions", base_url))
            .json(&block)
            .send()
            .await;
        ark_std::println!("Got response {:?}", res);
        Ok(())
    }
}
