use crate::art::PrivateZeroArt;
use crate::art::art_types::PrivateArt;
use crate::changes::branch_change::{BranchChange, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use std::rc::Rc;
use zrt_zk::EligibilityArtefact;

pub trait ArtBasicOps<G, R>
where
    G: AffineRepr,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
    ) -> Result<R, ArtError>;

    fn add_node(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;
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
    ) -> Result<BranchChange<G>, ArtError> {
        self.private_update_node_key(target_leaf, new_key, append_changes)
            .map(|(_, change, _)| change)
    }

    fn add_node(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        self.private_add_node(new_key).map(|(_, change, _)| change)
    }
}

impl<R> ArtBasicOps<CortadoAffine, PrivateBranchChange<CortadoAffine>>
    for PrivateZeroArt<CortadoAffine, R>
where
    R: Rng + ?Sized,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        _: bool,
    ) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        if self.marker_tree.data {
            return Err(ArtError::InvalidInput);
        }

        let eligibility = EligibilityArtefact::Member((
            self.upstream_art.get_leaf_secret_key(),
            self.upstream_art.get_leaf_public_key(),
        ));

        let (_, change, artefacts) = self
            .upstream_art
            .ephemeral_update_art_branch_with_leaf_secret_key(new_key, &target_leaf.get_path()?)?;

        Ok(PrivateBranchChange {
            branch_change: change,
            prover_branch: artefacts.to_prover_branch(&mut self.rng)?,
            eligibility,
            secret: new_key,
            prover_engine: Rc::clone(&self.prover_engine),
        })
    }

    fn add_node(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        if self.marker_tree.data {
            return Err(ArtError::InvalidInput);
        }

        let eligibility = EligibilityArtefact::Owner((
            self.upstream_art.get_leaf_secret_key(),
            self.upstream_art.get_leaf_public_key(),
        ));

        let (_, change, artefacts) = self.ephemeral_private_add_node(new_key)?;

        Ok(PrivateBranchChange {
            branch_change: change,
            prover_branch: artefacts.to_prover_branch(&mut self.rng)?,
            eligibility,
            secret: new_key,
            prover_engine: Rc::clone(&self.prover_engine),
        })
    }
}
