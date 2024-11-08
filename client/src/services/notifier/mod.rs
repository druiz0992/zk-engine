use std::marker::PhantomData;

use crate::{configuration::SequencerSettings, ports::notifier::Notifier};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use async_trait::async_trait;
use common::structs::Transaction;

#[derive(Clone, Debug)]
pub struct HttpNotifier<V> {
    pub base_url: String,
    _marker: std::marker::PhantomData<V>,
}

impl<V> HttpNotifier<V> {
    pub fn new(settings: SequencerSettings) -> Self {
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
        ark_std::println!("Got response {:?}", res);
        Ok(())
    }
}
