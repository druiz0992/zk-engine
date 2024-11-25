use super::test_app::ClientTestApp;
use client::ports::storage::TreeDB;
use curves::pallas::Fq;
use trees::MembershipPath;

impl ClientTestApp {
    pub async fn get_sibling_path(
        &self,
        block_number: u64,
        leaf_index: usize,
    ) -> Option<MembershipPath<Fq>> {
        let db_locked = self.db.lock().await;
        db_locked.get_sibling_path(&block_number, leaf_index)
    }

    pub async fn get_root(&self, block_number: u64) -> Option<Fq> {
        let db_locked = self.db.lock().await;
        db_locked.get_root(&block_number)
    }
}
