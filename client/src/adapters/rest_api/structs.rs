use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MintInput {
    pub value: String,
    pub token_id: String,
    pub compressed_public_key: String,
    pub salt: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MnemonicInput {
    pub mnemonic: String,
}
