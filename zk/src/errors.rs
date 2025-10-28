use thiserror::Error;

#[derive(Error, Debug)]
pub enum ZKError {
    #[error("bulletproofs R1CS error: {0}")]
    R1CSError(#[from] bulletproofs::r1cs::R1CSError),
    #[error("zkp error: {0}.")]
    ZKPError(#[from] zkp::ProofError),
    #[error("Provided aggregation is invalid.")]
    InvalidAggregation,
    #[error("User is not eligible for the operation.")]
    EligibilityError,
    #[error("Invalid proof type.")]
    InvalidProofType,
}
