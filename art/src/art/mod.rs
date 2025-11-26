//! Crate with ART types, which are build on top of the ART tree. Includes ART update operations
//! and other tools.

mod aggregations;
mod art_advanced_operations;
mod artefacts;
mod private_art;
mod public_art;

pub use art_advanced_operations::ArtAdvancedOps;
pub use private_art::{PrivateArt, ArtSecrets, ArtSecret};
pub use public_art::{ArtNodePreview, PublicArt, PublicArtPreview, PublicMergeData};
pub use aggregations::{AggregationContext};

pub(crate) use artefacts::{ProverArtefacts, VerifierArtefacts};

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
 