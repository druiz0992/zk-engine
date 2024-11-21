use ark_ec::{
    pairing::Pairing,
    short_weierstrass::{Affine, Projective, SWCurveConfig},
    CurveGroup,
};
use ark_ff::PrimeField;
use common::crypto::poseidon::constants::PoseidonParams;
use jf_plonk::nightfall::ipa_structs::{CommitKey, ProvingKey};
use jf_primitives::rescue::RescueParameter;
use jf_relation::gadgets::ecc::SWToTEConParam;
use zk_macros::sequencer_bounds;

#[sequencer_bounds]
#[derive(Debug, Default)]
pub struct RollupCommitKeys<V, VSW, P, SW> {
    pub pallas_commit_key: CommitKey<P>,
    pub vesta_commit_key: CommitKey<V>,
}

#[sequencer_bounds]
impl<V, VSW, P, SW> Clone for RollupCommitKeys<V, VSW, P, SW> {
    fn clone(&self) -> Self {
        Self {
            pallas_commit_key: self.pallas_commit_key.clone(),
            vesta_commit_key: self.vesta_commit_key.clone(),
        }
    }
}

#[sequencer_bounds]
#[derive(Debug)]
pub struct RollupProvingKeys<V, VSW, P, SW> {
    pub base_proving_key: ProvingKey<P>,
    pub bounce_proving_key: ProvingKey<V>,
    pub merge_proving_key: ProvingKey<P>,
    pub bounce_merge_proving_key: ProvingKey<V>,
}

#[sequencer_bounds]
impl<V, VSW, P, SW> Clone for RollupProvingKeys<V, VSW, P, SW> {
    fn clone(&self) -> Self {
        Self {
            base_proving_key: self.base_proving_key.clone(),
            bounce_proving_key: self.bounce_proving_key.clone(),
            merge_proving_key: self.merge_proving_key.clone(),
            bounce_merge_proving_key: self.bounce_merge_proving_key.clone(),
        }
    }
}
#[derive(Debug, Clone, Eq, Hash, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CircuitType {
    Mint,
    Transfer,
    BaseRollup,
    BounceRollup,
    MergeRollup,
    BounceMergeRollup,
}
