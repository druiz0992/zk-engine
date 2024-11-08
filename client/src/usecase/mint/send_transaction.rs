use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};
use common::structs::Transaction;

pub(crate) fn send_transaction_to_sequencer<V>(transaction: Transaction<V>)
where
    V: Pairing,
    <<V as Pairing>::G1 as CurveGroup>::Config: SWCurveConfig,
{
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        let res = client
            .post("http://127.0.0.1:4000/transactions")
            .json(&transaction)
            .send()
            .await;
        ark_std::println!("Got response {:?}", res);
    });
}
