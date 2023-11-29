use curves::{pallas::PallasConfig, vesta::VestaConfig};
use jf_plonk::nightfall::ipa_structs::{CommitKey, ProvingKey};

#[derive(Debug, Clone, Default)]
pub struct RollupCommitKeys {
    pub pallas_commit_key: CommitKey<PallasConfig>,
    pub vesta_commit_key: CommitKey<VestaConfig>,
}

#[derive(Debug, Clone)]
pub struct RollupProvingKeys {
    pub base_proving_key: ProvingKey<PallasConfig>,
    pub bounce_proving_key: ProvingKey<VestaConfig>,
    pub merge_proving_key: ProvingKey<PallasConfig>,
    pub bounce_merge_proving_key: ProvingKey<VestaConfig>,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum CircuitType {
    Mint,
    Transfer,
    BaseRollup,
    BounceRollup,
    MergeRollup,
    BounceMergeRollup,
}
