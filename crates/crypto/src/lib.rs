use thiserror::Error;
use zkp::ProofError;

pub mod x3dh;
pub mod schnorr;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("error in x3dh: {0}")]
    X3DHError(String),

    #[error("error hkdf::InvalidLength: {0}")]
    HKDFError(#[from] hkdf::InvalidLength),

    #[error("error ark_serialize::error::SerializationError: {0}")]
    SerialisationError(#[from] ark_serialize::SerializationError),

    #[error("error in Schnorr signature: {0}")]
    SchnorrError(String),

    #[error("error in zkp: {0}")]
    ProofError(#[from] ProofError),
}