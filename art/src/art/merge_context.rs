use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use tracing::debug;
use zrt_zk::art::ArtProof;
use zrt_zk::EligibilityRequirement;
use crate::art::art_node::ArtNode;
use crate::art::art_types::{PrivateArt, PublicArt};
use crate::art::ProverArtefacts;
use crate::changes::{ApplicableChange, VerifiableChange};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::recompute_artefacts;
use crate::TreeMethods;

pub struct PublicMergeContext<G>
where
    G: AffineRepr,
{
    pub(crate) base_art: PublicArt<G>,
    pub(crate) upstream_art: PublicArt<G>,
}

impl<G> PublicMergeContext<G>
where
    G: AffineRepr,
{
    pub fn new(base_art: PublicArt<G>) -> Self {
        let upstream_art = base_art.clone();
        Self {
            base_art,
            upstream_art,
        }
    }

    pub fn commit(&mut self) {
        self.upstream_art.get_mut_root().set_marker(false);
        self.base_art = self.upstream_art.clone();
    }

    pub fn discard(&mut self) {
        self.upstream_art.get_mut_root().set_marker(false);
        self.upstream_art = self.base_art.clone();
    }
}


impl<G> ApplicableChange<PublicMergeContext<G>> for BranchChange<G>
where
    G: AffineRepr
{
    fn apply(&self, art: &mut PublicMergeContext<G>) -> Result<(), ArtError> {
        if let BranchChangeType::AddMember = self.change_type {
            return Err(ArtError::InvalidMergeInput)
        }

        art.upstream_art.merge_by_marker(&self.public_keys, &self.node_index.get_path()?)
    }
}

// pub struct PrivateZeroArt<T, G>
pub struct PrivateMergeContext<G>
where
    G: AffineRepr,
{
    pub(crate) base_art: PrivateArt<G>,
    pub(crate) upstream_art: PrivateArt<G>,
    // pub(crate) proposed_secrets: Option<Vec<G::ScalarField>>,
}

impl<G> PrivateMergeContext<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn new(base_art: PrivateArt<G>) -> Self {
        let upstream_art = base_art.clone();

        Self {
            base_art,
            upstream_art,
            // proposed_secrets: None,
        }
    }

    pub fn commit(&mut self) {
        self.upstream_art.get_mut_root().set_marker(false);
        self.base_art = self.upstream_art.clone();
    }

    pub fn discard(&mut self) {
        self.upstream_art.get_mut_root().set_marker(false);
        self.upstream_art = self.base_art.clone();
    }

    /// Returns only new secrets from root to some node.
    pub(crate) fn get_updated_secrets(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<Vec<G::ScalarField>, ArtError> {
        let target_art = &self.base_art;
        let intersection = target_art.get_node_index().intersect_with(&changes.node_index)?;

        let mut partial_co_path = if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
            // partial_co_path.push(*public_key);
            vec![public_key.clone()]
        } else {
            // else it is or self update or AddMember, which is forbidden.
            vec![]
        };
        partial_co_path.append(&mut target_art.public_art.get_co_path_values(&intersection)?);

        let level_sk = target_art.secrets[target_art.secrets.len() - partial_co_path.len() - 1];

        let secrets = recompute_artefacts(level_sk, &partial_co_path)?.secrets;

        Ok(secrets[1..].to_vec())
    }

    pub(crate) fn update_secrets(&mut self, branch_change: &BranchChange<G>, merge_key: bool) -> Result<(), ArtError> {
        let secrets = self.get_updated_secrets(branch_change)?;
        // let merge_key = self.upstream_art.get_root().is_marked();

        for (sk, i) in secrets.iter().rev().zip((0..self.upstream_art.secrets.len()).rev()) {
            if merge_key {
                self.upstream_art.secrets[i] += sk;
            } else {
                self.upstream_art.secrets[i] = *sk;
            }
        }

        Ok(())

    }
}

impl<G> ApplicableChange<PrivateMergeContext<G>> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateMergeContext<G>) -> Result<(), ArtError> {
        if let BranchChangeType::AddMember = self.change_type {
            return Err(ArtError::InvalidMergeInput)
        }

        let merge_key = art.upstream_art.get_root().is_marked();
        art.upstream_art.public_art.merge_by_marker(&self.public_keys, &self.node_index.get_path()?)?;
        art.update_secrets(self, merge_key)?;

        Ok(())
    }
}


