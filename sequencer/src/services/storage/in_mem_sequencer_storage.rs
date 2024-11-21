use crate::ports::storage::{BlockStorage, GlobalStateStorage, TransactionStorage};
use common::structs::{Block, Transaction};
use curves::pallas::Fr;
use curves::vesta::VestaConfig;
use trees::membership_tree::Tree;
use trees::non_membership_tree::IndexedMerkleTree;

#[derive(Clone, Default)]
pub struct InMemStorage {
    pub blocks: Vec<Block<curves::vesta::Fr>>,
    pub mempool: Vec<Transaction<VestaConfig>>,
    pub past_txs: Vec<Transaction<VestaConfig>>,
    pub nullifier_tree: IndexedMerkleTree<Fr, 32>,
    pub commitment_tree: Tree<Fr, 8>,
    pub vk_tree: Tree<Fr, 8>,
}

impl InMemStorage {
    pub fn new() -> Self {
        Default::default()
    }
}

impl TransactionStorage<VestaConfig> for InMemStorage {
    fn get_transaction(&self) -> Option<Transaction<VestaConfig>> {
        todo!()
    }

    fn insert_transaction(&mut self, transaction: Transaction<VestaConfig>) {
        self.mempool.push(transaction);
    }

    fn get_mempool_transactions(&self) -> Vec<Transaction<VestaConfig>> {
        self.mempool.clone()
    }

    fn get_block_transaction(&self) -> Vec<Transaction<VestaConfig>> {
        todo!()
    }
    fn get_all_transactions(&self) -> Vec<Transaction<VestaConfig>> {
        let past_txs = self.past_txs.clone();
        let mempool_txs = self.mempool.clone();
        past_txs.into_iter().chain(mempool_txs).collect()
    }
}

impl BlockStorage<curves::vesta::Fr> for InMemStorage {
    fn get_block(&self, _blocknumber: u64) -> Option<Block<curves::vesta::Fr>> {
        todo!()
    }

    fn insert_block(&mut self, _block: Block<curves::vesta::Fr>) {
        todo!()
    }

    fn get_block_count(&self) -> u32 {
        todo!()
    }
}

impl GlobalStateStorage for InMemStorage {
    type CommitmentTree = Tree<Fr, 8>;
    type VkTree = Tree<Fr, 8>;
    type NullifierTree = IndexedMerkleTree<Fr, 32>;
    fn get_global_commitment_tree(&self) -> Self::CommitmentTree {
        self.commitment_tree.clone()
    }
    fn get_global_nullifier_tree(&self) -> Self::NullifierTree {
        self.nullifier_tree.clone()
    }
    fn get_vk_tree(&self) -> Self::VkTree {
        self.vk_tree.clone()
    }
    fn store_vk_tree(&mut self, vk_tree: Self::VkTree) {
        self.vk_tree = vk_tree;
    }
}
