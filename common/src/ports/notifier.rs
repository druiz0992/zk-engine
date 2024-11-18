use async_trait::async_trait;

#[async_trait]
pub trait Notifier: Clone + Send + Sync + 'static {
    type Info;

    async fn send_info(&self, info: Self::Info) -> anyhow::Result<()>;
}
