//! Crate with ART types, operations and tools.

mod art_advanced_operations;
mod art_basic_operations;
pub mod art_node;
pub mod art_types;
mod artefacts;
mod merge_context;
mod aggregation_context;

pub use art_advanced_operations::ArtAdvancedOps;
pub use art_basic_operations::ArtBasicOps;
pub use artefacts::{ProverArtefacts, VerifierArtefacts};
pub use merge_context::{PublicZeroArt, PrivateZeroArt};
pub use aggregation_context::{AggregationContext};

/// Helper data type, returned after the most art update operations.
pub(crate) type ArtLevel<G> = (
    Vec<Box<crate::art::art_node::ArtNode<G>>>,
    Vec<<G as ark_ec::AffineRepr>::ScalarField>,
);
pub(crate) type ArtUpdateOutput<G> = (
    <G as ark_ec::AffineRepr>::ScalarField,
    crate::changes::branch_change::BranchChange<G>,
    ProverArtefacts<G>,
);
