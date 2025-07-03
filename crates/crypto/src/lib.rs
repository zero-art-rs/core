use thiserror::Error;

pub mod x3dh;


#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("error in x3dh: {0}")]
    X3DHError(String),

    #[error("error hkdf::InvalidLength: {0}")]
    HKDFError(#[from] hkdf::InvalidLength),

    #[error("error ark_serialize::error::SerializationError: {0}")]
    SerialisationError(#[from] ark_serialize::SerializationError)
}