use crate::art::EligibilityProofInput;
use crate::art::art_node::{ArtNode, LeafStatus};
use crate::art::art_types::{PrivateArt, PrivateZeroArt};
use crate::art::branch_change::{BranchChange, VerifiableBranchChange};
use crate::art::tree_methods::TreeMethods;
use crate::errors::ARTError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use std::ops::Mul;
use tracing::debug;
use zrt_zk::art::{art_prove, art_verify};

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

impl<G> ArtBasicOps<G, BranchChange<G>> for PrivateArt<G>
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
    ) -> Result<BranchChange<G>, ARTError> {
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
    ) -> Result<BranchChange<G>, ARTError> {
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
    ) -> Result<BranchChange<G>, ARTError> {
        todo!()
    }

    fn draft_add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        todo!()
    }
}

impl<'a, R> ArtBasicOps<CortadoAffine, VerifiableBranchChange> for PrivateZeroArt<'a, R>
where
    R: ?Sized + Rng,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        append_changes: bool,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let user_secret_key = self.private_art.get_leaf_secret_key()?;

        let path = target_leaf.get_path()?;
        let (_, change, artefacts) = self.private_art.update_art_branch_with_leaf_secret_key(
            new_key,
            &path,
            append_changes,
        )?;

        self.private_art.zip_update_path_secrets(
            artefacts.secrets.clone(),
            &change.node_index,
            append_changes,
        )?;

        let proof = art_prove(
            self.proof_basis.clone(),
            ad,
            &artefacts.to_prover_branch(self.rng)?,
            vec![
                CortadoAffine::generator()
                    .mul(user_secret_key)
                    .into_affine(),
            ],
            vec![user_secret_key],
        )?;

        Ok({
            VerifiableBranchChange {
                branch_change: change,
                proof,
            }
        })
    }

    fn add_node(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let user_secret_key = self.private_art.get_leaf_secret_key()?;

        let mut path = match self.get_public_art().find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => self.get_public_art().find_path_to_lowest_leaf()?,
        };

        let new_leaf = ArtNode::new_leaf(CortadoAffine::generator().mul(new_key).into_affine());
        let target_leaf = self.get_mut_node_at(&path)?;

        if !target_leaf.is_leaf() {
            return Err(ARTError::LeafOnly);
        }

        let extend_node = matches!(target_leaf.get_status(), Some(LeafStatus::Active));
        target_leaf.extend_or_replace(new_leaf)?;

        if extend_node {
            path.push(Direction::Right);
        }

        let (_, change, artefacts) = self
            .private_art
            .update_art_branch_with_leaf_secret_key(new_key, &path, false)?;

        if self
            .private_art
            .get_node_index()
            .is_subpath_of(&change.node_index)?
        {
            let mut new_path_secrets =
                vec![*self.private_art.secrets.first().ok_or(ARTError::EmptyART)?];
            new_path_secrets.append(self.private_art.secrets.clone().as_mut());
            self.private_art.secrets = new_path_secrets;
        }
        self.private_art.update_node_index()?;

        self.private_art.zip_update_path_secrets(
            artefacts.secrets.clone(),
            &change.node_index,
            false,
        )?;

        let proof = art_prove(
            self.proof_basis.clone(),
            ad,
            &artefacts.to_prover_branch(self.rng)?,
            vec![
                CortadoAffine::generator()
                    .mul(user_secret_key)
                    .into_affine(),
            ],
            vec![user_secret_key],
        )?;

        Ok({
            VerifiableBranchChange {
                branch_change: change,
                proof,
            }
        })
    }

    fn draft_update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        todo!()
    }

    fn draft_add_node(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        todo!()
    }
}
