pub mod applicable_change;
pub mod art_advanced_operations;
pub mod art_basic_operations;
pub mod art_node;
pub mod art_types;
pub mod branch_change;
pub mod tree_node;

pub enum EligibilityProofInput {
    OwnerLeafKey,
}

/// Helper data type, returned after the most art update operations.
pub(crate) type ArtLevel<G> = (Vec<Box<ArtNode<G>>>, Vec<<G as AffineRepr>::ScalarField>);
pub(crate) type ArtUpdateOutput<G> = (
    <G as AffineRepr>::ScalarField,
    BranchChanges<G>,
    ProverArtefacts<G>,
);

use crate::art::ProverArtefacts;
use crate::zrt_art::art_node::ArtNode;
use crate::zrt_art::branch_change::BranchChanges;
use ark_ec::AffineRepr;
pub use art_basic_operations::ArtBasicOps;
