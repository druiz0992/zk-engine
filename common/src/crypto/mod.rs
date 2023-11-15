pub mod poseidon;

mod crypto_errors {
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum CryptoError {
        #[error("An error happened while hashing: {0}")]
        HashError(String),
    }
}
