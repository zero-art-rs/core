//! Crate with ART types, operations and tools.

mod aggregation_context;
mod art_advanced_operations;
mod art_basic_operations;
pub mod art_node;
pub mod art_types;
mod artefacts;
mod merge_context;

pub use aggregation_context::AggregationContext;
pub use art_advanced_operations::ArtAdvancedOps;
pub use art_basic_operations::ArtBasicOps;
pub use artefacts::{ProverArtefacts, VerifierArtefacts};
pub use merge_context::{PrivateZeroArt, PublicZeroArt};
pub(crate) use merge_context::{
    extend_marker_node, handle_potential_art_node_extension_on_add_member,
    handle_potential_marker_tree_node_extension_on_add_member,
    insert_first_secret_at_start_if_need,
};

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
