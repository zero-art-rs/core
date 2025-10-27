pub mod art_advanced_operations;
pub mod art_basic_operations;
pub mod art_node;
pub mod art_types;
pub mod artefacts;

pub use art_advanced_operations::ArtAdvancedOps;
pub use art_basic_operations::ArtBasicOps;
pub use artefacts::{ProverArtefacts, VerifierArtefacts};

pub enum EligibilityProofInput {
    OwnerLeafKey,
}

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
