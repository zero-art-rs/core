use crate::art::ARTNode;
use crate::errors::ARTError;
use crate::node_index::{Direction, NodeIndex};
use crate::zrt_art::EligibilityProofInput;
use crate::zrt_art::art_node::{ArtNode, LeafStatus};
use crate::zrt_art::art_types::PrivateArt;
use crate::zrt_art::branch_change::BranchChanges;
use crate::zrt_art::tree_node::TreeMethods;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use tracing::debug;
// art.update_node_key::<VerifiableBranchChanges>(...)
//
// VerifiableBranchChanges::update_node_key(&art, ...)
// VerifiableBranchChanges::mut_update_node_key(&mut art, ...)

pub trait ArtBasicOps<G, R>
where
    G: AffineRepr,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn draft_update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn draft_add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;
}

impl<G> ArtBasicOps<G, BranchChanges<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let path = target_leaf.get_path()?;
        let (_, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, append_changes)?;

        self.zip_update_path_secrets(
            artefacts.secrets.clone(),
            &changes.node_index,
            append_changes,
        )?;

        Ok(changes)
    }

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let mut path = match self.public_art.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => self.public_art.find_path_to_lowest_leaf()?,
        };

        let new_leaf = ArtNode::new_leaf(G::generator().mul(new_key).into_affine());
        let target_leaf = self.get_mut_node_at(&path)?;

        if !target_leaf.is_leaf() {
            return Err(ARTError::LeafOnly);
        }

        let extend_node = matches!(target_leaf.get_status(), Some(LeafStatus::Active));
        target_leaf.extend_or_replace(new_leaf)?;

        self.public_art.update_branch_weight(&path, false)?;

        if extend_node {
            path.push(Direction::Right);
        }

        let (_, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, false)?;

        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            let mut new_path_secrets = vec![*self.secrets.first().ok_or(ARTError::EmptyART)?];
            new_path_secrets.append(self.secrets.clone().as_mut());
            self.secrets = new_path_secrets;
        }
        self.update_node_index()?;

        self.zip_update_path_secrets(artefacts.secrets.clone(), &changes.node_index, false)?;

        Ok(changes)
    }

    fn draft_update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        todo!()
    }

    fn draft_add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        todo!()
    }
}
