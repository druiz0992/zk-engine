use super::test_app::ClientTestApp;
use client::ports::committable::Committable;
use client::ports::storage::PreimageDB;
use client::ports::storage::StoredPreimageInfo;
use client::ports::storage::StoredPreimageInfoVector;
use curves::pallas::PallasConfig;

impl ClientTestApp {
    pub async fn get_preimages(&self) -> StoredPreimageInfoVector<PallasConfig> {
        let db_locked = self.db.lock().await;
        db_locked.get_all_preimages()
    }

    pub async fn insert_preimages(
        &self,
        preimages: Vec<StoredPreimageInfo<PallasConfig>>,
    ) -> Result<(), String> {
        let mut db_locked = self.db.lock().await;
        for preimage in preimages {
            let key = preimage
                .preimage
                .commitment_hash()
                .map_err(|e| e.to_string())?;
            db_locked.insert_preimage(key.0, preimage);
        }
        Ok(())
    }
}
