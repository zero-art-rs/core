pub mod applicable_change;
pub mod art_advanced_operations;
pub mod art_basic_operations;
pub mod art_node;
pub mod art_types;
pub mod artefacts;
pub mod branch_change;
pub mod tree_methods;
pub mod verifiable_change;

pub enum EligibilityProofInput {
    OwnerLeafKey,
}

/// Helper data type, returned after the most art update operations.
pub(crate) type ArtLevel<G> = (Vec<Box<ArtNode<G>>>, Vec<<G as AffineRepr>::ScalarField>);
pub(crate) type ArtUpdateOutput<G> = (
    <G as AffineRepr>::ScalarField,
    BranchChange<G>,
    ProverArtefacts<G>,
);

use crate::art::art_node::ArtNode;
use crate::art::artefacts::ProverArtefacts;
use crate::art::branch_change::BranchChange;
use ark_ec::AffineRepr;
pub use art_basic_operations::ArtBasicOps;
