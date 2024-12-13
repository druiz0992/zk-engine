use crate::sequencer::test_app::SequencerTestApp;
use anyhow::Result;
use ark_ff::Zero;
use common::structs::{Block, Transaction};
use curves::{pallas::Fq, vesta::VestaConfig};
use jf_utils::field_switching;
use plonk_prover::rollup::circuits::client_input;
use sequencer::ports::storage::BlockStorage;
use sequencer::ports::storage::GlobalStateStorage;
use trees::{AppendTree, Tree};

impl SequencerTestApp {
    pub async fn post_sequence(&self) -> Result<Block<curves::vesta::Fr>> {
        let response = self
            .api_client
            .post(format!("{}/sequence", self.address))
            .send()
            .await
            .unwrap();

        if !response.status().is_success() {
            return Err(anyhow::anyhow!("Sequencer returned {}", response.status()));
        }

        let block = response
            .json::<Block<curves::vesta::Fr>>()
            .await
            .map_err(|_| anyhow::anyhow!("Error serializing Block from sequencer"))?;

        Ok(block)
    }

    pub async fn new_block(&self, transactions: &[Transaction<VestaConfig>]) -> Result<Block<Fq>> {
        let mut db_locked = self.db.lock().await;
        let mut nullifier_tree = db_locked.get_global_nullifier_tree();

        let mut nullifiers: Vec<Fq> = vec![];
        for transaction in transactions {
            let mut transaction_nullifiers = transaction
                .nullifiers
                .iter()
                .map(|n| n.0)
                .filter(|&n| n != Fq::zero())
                .collect::<Vec<_>>();
            client_input::update_nullifier_tree::<VestaConfig, 32>(
                &mut nullifier_tree,
                &transaction_nullifiers,
            )
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
            nullifiers.append(&mut transaction_nullifiers);
        }
        let commitments = transactions
            .iter()
            .flat_map(|tx| tx.commitments.iter().map(|c| c.0))
            .filter(|&c| c != Fq::zero())
            .collect::<Vec<_>>();
        let local_commitment_tree: Tree<Fq, 8> = Tree::from_leaves(commitments.clone());
        let local_commitment_tree_root = local_commitment_tree.root();
        let block_count = db_locked.get_block_count();
        let mut global_commitment_tree = db_locked.get_global_commitment_tree();
        global_commitment_tree.append_leaf(field_switching(&local_commitment_tree_root));
        //db_locked.store_global_commitment_tree(global_commitment_tree);

        let block = Block {
            block_number: block_count,
            commitments,
            nullifiers,
            commitment_root: local_commitment_tree_root,
        };
        db_locked.insert_block(block.clone());
        db_locked.past_txs.append(&mut transactions.to_vec());

        Ok(block)
    }
}
