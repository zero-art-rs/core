use thiserror::Error;

#[derive(Error, Debug)]
pub enum ARTNodeError {
    #[error("Given parameters are invalid")]
    InvalidParameters,
    #[error("The method is callable only for leaves")]
    LeafOnly,
    #[error("The method is callable only for internal nodes")]
    InternalNodeOnly,
}

#[derive(Error, Debug)]
pub enum ARTError {
    #[error("Art logic Error.")]
    ARTLogicError,
    #[error("Invalid input provided")]
    InvalidInput,
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("Serde JSON error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Node error: {0}")]
    Node(#[from] ARTNodeError),
    #[error("Cant find path to given node.")]
    PathNotExists,
    #[error("Cant remove th node. It isn't close enough.")]
    RemoveError,
}
