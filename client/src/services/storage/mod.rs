pub mod in_mem_storage {
    use std::collections::HashMap;

    use ark_ec::{pairing::Pairing, short_weierstrass::SWCurveConfig, CurveGroup};

    use crate::{domain::Preimage, ports::storage::PreimageDB};

    pub struct InMemStorage<VSW>
    where
        VSW: SWCurveConfig,
    {
        pub preimage_db: HashMap<String, Preimage<VSW>>,
    }

    impl<VSW> InMemStorage<VSW>
    where
        VSW: SWCurveConfig,
    {
        pub fn new() -> Self {
            Self {
                preimage_db: HashMap::new(),
            }
        }
    }

    impl<VSW> PreimageDB for InMemStorage<VSW>
    where
        VSW: SWCurveConfig,
    {
        type E = VSW;

        fn get_value(&self, value: VSW::BaseField) -> Option<Preimage<VSW>> {
            todo!()
        }

        fn get_spendable(&self) -> Option<Vec<Preimage<VSW>>> {
            todo!()
        }

        fn get_preimage(&self, key: VSW::BaseField) -> Option<Preimage<VSW>> {
            self.preimage_db.get(&key.to_string()).cloned()
        }

        fn insert_preimage(&mut self, key: VSW::BaseField, preimage: Preimage<VSW>) -> Option<()> {
            // We check it doesnt already exist so we dont overwrite.
            if self.preimage_db.contains_key(&key.to_string()) {
                return None;
            }
            // Insert returns None if there wasnt a key.
            let insert = self.preimage_db.insert(key.to_string(), preimage);
            Some(())
        }

        fn get_all_preimages(&self) -> Vec<Preimage<VSW>> {
            let mut v = Vec::new();
            self.preimage_db.values().for_each(|&x| v.push(x.clone()));
            v
        }
    }
}
