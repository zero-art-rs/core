//! Crate with ART types, which are build on top of the ART tree. Includes ART update operations
//! and other tools.

mod aggregations;
mod art_advanced_operations;
mod art_basic_operations;
mod art_types;
mod artefacts;
mod private_art;
mod public_art;
mod zero_art;

// pub use aggregations::AggregationContext;
// pub use art_advanced_operations::ArtAdvancedOps;
// pub use art_basic_operations::ArtBasicOps;
pub(crate) use artefacts::{ProverArtefacts, VerifierArtefacts};
pub use private_art::PrivateArt;
pub(crate) use public_art::PublicMergeData;
pub use public_art::{ArtNodePreview, PublicArt, PublicArtPreview};
// pub use zero_art::{PrivateZeroArt, PublicZeroArt};
// pub(crate) use zero_art::{
//     handle_potential_art_node_extension_on_add_member,
//     handle_potential_marker_tree_node_extension_on_add_member, update_secrets_if_need,
// };

/// Helper data type, returned after the most art update operations.
pub(crate) type ArtLevel<G> = (
    Vec<Box<crate::art_node::ArtNode<G>>>,
    Vec<<G as ark_ec::AffineRepr>::ScalarField>,
);
pub(crate) type ArtUpdateOutput<G> = (
    <G as ark_ec::AffineRepr>::ScalarField,
    crate::changes::branch_change::BranchChange<G>,
    ProverArtefacts<G>,
);
