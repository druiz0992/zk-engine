pub mod poseidon;

pub mod crypto_errors {
    use thiserror::Error;
    #[derive(Error, Debug)]
    pub enum CryptoError {
        #[error("An error happened while hashing")]
        HashError(String),
    }
}
