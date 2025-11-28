//! Crate with ART types, which are build on top of the ART tree. Includes ART update operations
//! and other tools.

mod aggregations;
mod art_advanced_operations;
mod artefacts;
mod private_art;
mod public_art;

pub use aggregations::AggregationContext;
pub use art_advanced_operations::ArtAdvancedOps;
pub use private_art::{ArtSecretPreview, ArtSecrets, PrivateArt, PrivateArtApplySnapshot};
pub use public_art::{ArtNodePreview, PublicArt, PublicArtPreview, PublicMergeData, PublicArtApplySnapshot};

pub(crate) use artefacts::ProverArtefacts;

/// Helper data type, returned after the most art update operations.
pub(crate) type ArtLevel<G> = (
    Vec<Box<crate::art_node::ArtNode<G>>>,
    Vec<<G as ark_ec::AffineRepr>::ScalarField>,
);
