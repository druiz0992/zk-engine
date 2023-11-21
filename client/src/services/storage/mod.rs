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

        fn get_preimage(&self, key: VSW::ScalarField) -> Option<Preimage<VSW>> {
            todo!()
        }

        fn insert_preimage(
            &mut self,
            key: VSW::ScalarField,
            preimage: Preimage<VSW>,
        ) -> Option<()> {
            todo!()
        }

        fn get_all_preimages(&self) -> Vec<Preimage<VSW>> {
            let mut v = Vec::new();
            self.preimage_db.values().for_each(|&x| v.push(x.clone()));
            v
        }
    }
}
