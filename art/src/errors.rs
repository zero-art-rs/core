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
    #[error("Something vent wrong, while performing operations")]
    ARTLogicError,
    #[error("Invalid input provided.")]
    InvalidInput,
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("Serde JSON error: {0}.")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Node error: {0}.")]
    Node(#[from] ARTNodeError),
    #[error("Cant find path to given node.")]
    PathNotExists,
    #[error("Failed to convert &[u8] into &[u8;32] {0}.")]
    ConversionError(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point.")]
    XCoordinateError,
    #[error("No changes provided in given BranchChanges structure.")]
    NoChanges,
    #[error("The art has no nodes.")]
    EmptyART,
    #[error("Can't apply blank operation change to itself.")]
    InapplicableBlanking,
    #[error("Can't apply key operation update change to itself.")]
    InapplicableKeyUpdate,
    #[error("Can't apply leave operation update change to itself.")]
    InapplicableLeave,
    #[error("The method can't be applied to the non leaf node.")]
    NonLeafNode,
    #[error("Cant merge given changes.")]
    MergeInput,
}
