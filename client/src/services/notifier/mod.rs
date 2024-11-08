use crate::{configuration::SequencerSettings, ports::notifier::Notifier};
use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use async_trait::async_trait;
use common::structs::Transaction;

#[derive(Clone, Debug)]
pub struct HttpNotifier {
    pub base_url: String,
}

impl HttpNotifier {
    pub fn new(settings: SequencerSettings) -> Self {
        let _timeout = settings.timeout();
        Self {
            base_url: settings.base_url,
        }
    }
}

#[async_trait]
impl<P: Pairing> Notifier<P> for HttpNotifier
where
    <<P as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    #[tracing::instrument(name = "Send notification", skip(transaction))]
    async fn send_transaction(&self, transaction: Transaction<P>) -> anyhow::Result<()> {
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
