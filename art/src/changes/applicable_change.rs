use crate::TreeMethods;
use crate::art::art_node::LeafStatus;
use crate::art::art_types::{PrivateArt, PublicArt};
use crate::art::{
    AggregationContext, PrivateZeroArt, PublicZeroArt,
    handle_potential_art_node_extension_on_add_member,
    handle_potential_marker_tree_node_extension_on_add_member,
    insert_first_secret_at_start_if_need,
};
use crate::changes::aggregations::AggregatedChange;
use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::Direction;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use std::mem;

/// A trait for ART change that can be applied to the ART.
///
/// This trait represents an ability of change to update some instance of ART of type `T`.
///
/// # Type Parameters
/// * `T` – The type of the ART tree type being updated.
pub trait ApplicableChange<T> {
    /// Apply a change to the provided art.
    fn apply(&self, art: &mut T) -> Result<(), ArtError>;
}

impl<G> ApplicableChange<PublicArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && let Some(LeafStatus::Blank) = art.get_node(&self.node_index)?.get_status()
        {
            art.update_with_options(self, true, false)
        } else {
            art.update_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && matches!(
                art.public_art.get_node(&self.node_index)?.get_status(),
                Some(LeafStatus::Blank)
            )
        {
            art.update_private_art_with_options(self, true, false)
        } else {
            art.update_private_art_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PublicArt<G>> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        self.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        self.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt<CortadoAffine>> for AggregatedChange<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt<CortadoAffine>) -> Result<(), ArtError> {
        self.update_public_art(&mut art.upstream_art)?;
        art.commit();

        Ok(())
    }
}

impl<G, R> ApplicableChange<PrivateZeroArt<G, R>> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<(), ArtError> {
        self.update_private_art(&mut art.upstream_art)?;
        art.commit();

        Ok(())
    }
}

impl<G, R1, R2> ApplicableChange<PrivateZeroArt<G, R1>> for AggregationContext<PrivateArt<G>, G, R2>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R1: Rng + ?Sized,
    R2: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<G, R1>) -> Result<(), ArtError> {
        art.upstream_art = self.operation_tree.clone();
        art.commit();

        Ok(())
    }
}

impl<G, R> ApplicableChange<PrivateArt<G>> for AggregationContext<PrivateArt<G>, G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        let _ = mem::replace(art, self.operation_tree.clone());

        Ok(())
    }
}

impl<G> ApplicableChange<PublicZeroArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicZeroArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::AddMember = &self.change_type {
            if art.marker_tree.data {
                return Err(ArtError::InvalidMergeInput);
            }

            let mut target_path = self.node_index.get_path()?;
            let last_direction = target_path.pop().ok_or(ArtError::NoChanges)?;

            handle_potential_art_node_extension_on_add_member(
                &mut art.upstream_art,
                &target_path,
                last_direction,
            )?;

            handle_potential_marker_tree_node_extension_on_add_member(
                &mut art.marker_tree,
                &target_path,
                last_direction,
            )?;
        }

        art.upstream_art.merge_by_marker(
            &self.public_keys,
            &self.node_index.get_path()?,
            &mut art.marker_tree,
        )?;

        PublicArt::change_leaf_status_by_change_type(
            art.upstream_art
                .get_mut_node_at(&self.node_index.get_path()?)?,
            &self.change_type,
        )?;

        Ok(())
    }
}

impl<G, R> ApplicableChange<PrivateZeroArt<G, R>> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<(), ArtError> {
        if let BranchChangeType::AddMember = &self.change_type {
            if art.marker_tree.data {
                return Err(ArtError::InvalidMergeInput);
            }

            let mut target_path = self.node_index.get_path()?;
            let last_direction = target_path.pop().ok_or(ArtError::NoChanges)?;

            let extension_was_performed = handle_potential_art_node_extension_on_add_member(
                &mut art.upstream_art.public_art,
                &target_path,
                last_direction,
            )?;

            handle_potential_marker_tree_node_extension_on_add_member(
                &mut art.marker_tree,
                &target_path,
                last_direction,
            )?;

            if extension_was_performed {
                let insertion_was_performed =
                    insert_first_secret_at_start_if_need(&mut art.upstream_art, &target_path)?;
                if insertion_was_performed {
                    art.upstream_art.node_index.push(Direction::Left);
                }
            }
        }

        let merge_key = art.marker_tree.data;
        art.upstream_art.public_art.merge_by_marker(
            &self.public_keys,
            &self.node_index.get_path()?,
            &mut art.marker_tree,
        )?;

        PublicArt::change_leaf_status_by_change_type(
            art.upstream_art
                .get_mut_node_at(&self.node_index.get_path()?)?,
            &self.change_type,
        )?;

        let updated_secrets = art.get_updated_secrets(&self)?;
        art.update_secrets(&updated_secrets, merge_key)?;

        Ok(())
    }
}

impl<G> ApplicableChange<PublicZeroArt<G>> for PrivateBranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicZeroArt<G>) -> Result<(), ArtError> {
        self.branch_change.apply(art)
    }
}

impl<G, R> ApplicableChange<PrivateZeroArt<G, R>> for PrivateBranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<(), ArtError> {
        if self.branch_change.change_type == BranchChangeType::UpdateKey
            || art.base_art.node_index == self.branch_change.node_index
        {
            return self.inner_apply_own_key_update(art, self.secret);
        }

        self.branch_change.apply(art)
    }
}
