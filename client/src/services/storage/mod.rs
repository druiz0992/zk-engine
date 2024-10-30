pub mod in_mem_storage {
    use std::{collections::HashMap, fmt::Debug};

    use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
    use ark_ff::PrimeField;
    use common::{crypto::poseidon::constants::PoseidonParams, structs::Block};
    use trees::{
        membership_tree::{MembershipTree, Tree},
        tree::AppendTree,
        MembershipPath,
    };

    use crate::{
        ports::storage::{KeyDB, PreimageDB, StoredPreimageInfo, StoredPreimageInfoVector, TreeDB},
        services::user_keys::UserKeys,
    };

    pub struct InMemStorage<VSW, F>
    where
        VSW: SWCurveConfig<BaseField = F>,
        F: PrimeField,
    {
        pub preimage_db: HashMap<String, StoredPreimageInfo<VSW>>,
        pub commitment_tree_db: HashMap<u64, Tree<F, 8>>,
        pub key_db: HashMap<Affine<VSW>, UserKeys<VSW>>,
    }

    impl<VSW, F> InMemStorage<VSW, F>
    where
        VSW: SWCurveConfig<BaseField = F>,
        F: PrimeField,
    {
        pub fn new() -> Self {
            Self {
                preimage_db: HashMap::new(),
                commitment_tree_db: HashMap::new(),
                key_db: HashMap::new(),
            }
        }
    }

    impl<VSW, F> PreimageDB for InMemStorage<VSW, F>
    where
        VSW: SWCurveConfig<BaseField = F>,
        F: PrimeField,
    {
        type E = VSW;

        fn get_value(&self, _value: VSW::BaseField) -> Option<StoredPreimageInfo<VSW>> {
            todo!()
        }

        fn get_spendable(&self) -> Option<StoredPreimageInfoVector<VSW>> {
            todo!()
        }

        fn get_preimage(&self, key: VSW::BaseField) -> Option<StoredPreimageInfo<VSW>> {
            self.preimage_db.get(&key.to_string()).cloned()
        }

        fn insert_preimage(
            &mut self,
            key: VSW::BaseField,
            preimage: StoredPreimageInfo<VSW>,
        ) -> Option<()> {
            // We check it doesnt already exist so we dont overwrite.
            if self.preimage_db.contains_key(&key.to_string()) {
                return None;
            }
            // Insert returns None if there wasnt a key.
            let _insert = self.preimage_db.insert(key.to_string(), preimage);
            Some(())
        }

        fn get_all_preimages(&self) -> StoredPreimageInfoVector<VSW> {
            let mut v = Vec::new();
            self.preimage_db.values().for_each(|&x| v.push(x.clone()));
            v
        }

        fn update_preimages(&mut self, block: Block<F>) {
            // Find all commitments in block and set to them to spendable
            block.commitments.iter().enumerate().for_each(|(i, c)| {
                if let Some(preimage) = self.preimage_db.get_mut(&c.to_string()) {
                    preimage.block_number = Some(block.block_number);
                    preimage.leaf_index = Some(i);
                }
            });
            // Find all nullifiers in block and set to them to spent
            block.nullifiers.iter().for_each(|&n| {
                if let Some(preimage) = self.preimage_db.get_mut(&n.to_string()) {
                    if preimage.nullifier == n {
                        preimage.spent = true;
                    }
                }
            });
        }
    }

    impl<VSW, F> TreeDB for InMemStorage<VSW, F>
    where
        VSW: SWCurveConfig<BaseField = F>,
        F: PrimeField + PoseidonParams<Field = F>,
    {
        type F = F;

        fn get_sibling_path(
            &self,
            block_number: &u64,
            leaf_index: usize,
        ) -> Option<MembershipPath<Self::F>> {
            self.commitment_tree_db
                .get(block_number)
                .and_then(|t| t.membership_witness(leaf_index))
        }

        fn add_block_leaves(&mut self, leaves: Vec<Self::F>, block_number: u64) -> Option<()> {
            let tree = Tree::from_leaves(leaves);
            if self.commitment_tree_db.contains_key(&block_number) {
                return None;
            }
            self.commitment_tree_db.insert(block_number, tree);
            Some(())
        }

        fn get_root(&self, block_number: &u64) -> Option<Self::F> {
            if !self.commitment_tree_db.contains_key(block_number) {
                return None;
            }
            self.commitment_tree_db.get(block_number).map(|t| t.root())
        }
    }

    impl<VSW, F> KeyDB for InMemStorage<VSW, F>
    where
        VSW: SWCurveConfig<BaseField = F> + Debug,
        F: PrimeField,
    {
        type E = VSW;
        type Key = UserKeys<VSW>;

        fn get_key(&self, public_key: Affine<VSW>) -> Option<Self::Key> {
            self.key_db.get(&public_key).cloned()
        }

        fn insert_key(&mut self, key: Affine<VSW>, value: Self::Key) -> Option<()> {
            if self.key_db.contains_key(&key) {
                return None;
            }
            self.key_db.insert(key, value);
            Some(())
        }
    }
}
