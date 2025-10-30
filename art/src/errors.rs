//! This module provides error type, which is returned by the whole crate. Other errors
//! are converted to it.

use bulletproofs::r1cs::R1CSError;
use thiserror::Error;
use zrt_zk::errors::ZKError;

#[derive(Error, Debug)]
pub enum ArtError {
    #[error("Something vent wrong, while performing operations")]
    ArtLogic,
    #[error("Invalid input provided.")]
    InvalidInput,
    #[error("Fail to update. Path to user leaf is a subpath of updated path.")]
    SubPath,
    #[error("Postcard error: {0}")]
    Postcard(#[from] postcard::Error),
    #[error("Serde JSON error: {0}.")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Cant find path to the node.")]
    PathNotExists,
    #[error("Failed to convert &[u8] into &[u8;32] {0}.")]
    Conversion(#[from] std::array::TryFromSliceError),
    #[error("Failed to retrieve x coordinate of a point.")]
    XCoordinate,
    #[error("No changes provided in given BranchChanges structure.")]
    NoChanges,
    #[error("The art has no nodes.")]
    EmptyArt,
    #[error("Can't apply blank operation change to itself.")]
    InapplicableBlanking,
    #[error("Can't apply key operation update change to itself.")]
    InapplicableKeyUpdate,
    #[error("Can't apply leave operation update change to itself.")]
    InapplicableLeave,
    #[error("The method can't be applied to the non leaf node.")]
    LeafOnly,
    #[error("The method can't be applied to the leaf node.")]
    InternalNodeOnly,
    #[error("Can't merge given changes.")]
    InvalidMergeInput,
    #[error("Fail to update tree_ds tree.")]
    TreeDs,
    #[error("Provided aggregation is invalid.")]
    InvalidAggregation,
    #[error("R1CSError: {0}")]
    R1CS(#[from] R1CSError),
    #[error("ZKError: {0}")]
    Zk(#[from] ZKError),
}
