mod art_node;
mod art_root_key;
mod artefacts;
mod branch_changes;
mod private_art;
mod public_art;

pub use art_node::{ARTNode, LeafIter, LeafIterWithPath, LeafStatus, NodeIter, NodeIterWithPath};
pub use art_root_key::ARTRootKey;
pub use artefacts::{ProverArtefacts, VerifierArtefacts};
pub use branch_changes::{BranchChanges, BranchChangesType, BranchChangesTypeHint};
pub use private_art::PrivateART;
pub use public_art::PublicART;

/// Helper data type, returned after the most art update operations.
pub type UpdateData<G> = (ARTRootKey<G>, BranchChanges<G>, ProverArtefacts<G>);
