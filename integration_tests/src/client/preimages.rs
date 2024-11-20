use super::test_app::ClientTestApp;
use client::ports::storage::PreimageDB;
use client::ports::storage::StoredPreimageInfoVector;
use curves::pallas::PallasConfig;

impl ClientTestApp {
    pub async fn get_preimages(&self) -> StoredPreimageInfoVector<PallasConfig> {
        let db_locked = self.db.lock().await;
        db_locked.get_all_preimages()
    }
}
