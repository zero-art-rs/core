//! Crate with ART types, operations and tools.

mod aggregations;
mod art_advanced_operations;
mod art_basic_operations;
pub mod art_node;
pub mod art_types;
mod artefacts;
mod zero_art;

pub use aggregations::AggregationContext;
pub use art_advanced_operations::ArtAdvancedOps;
pub use art_basic_operations::ArtBasicOps;
pub use artefacts::{ProverArtefacts, VerifierArtefacts};
pub use zero_art::{PrivateZeroArt, PublicZeroArt};
pub(crate) use zero_art::{
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
