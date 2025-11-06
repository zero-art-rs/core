use crate::TreeMethods;
use crate::art::art_node::{ArtNode, LeafStatus};
use crate::art::art_types::{PrivateArt, PublicArt};
use crate::art::{AggregationContext, PrivateZeroArt, PublicZeroArt};
use crate::changes::aggregations::AggregatedChange;
use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::CortadoAffine;

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

impl<T1, T2, R> ApplicableChange<T1> for AggregationContext<T2, CortadoAffine, R>
where
    R: Rng + ?Sized,
    AggregatedChange<CortadoAffine>: ApplicableChange<T1>,
{
    fn apply(&self, art: &mut T1) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(&self.prover_aggregation)?;
        plain_aggregation.apply(art)
    }
}

impl<G> ApplicableChange<PublicZeroArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicZeroArt<G>) -> Result<(), ArtError> {
        if art.marker_tree.data {
            return Err(ArtError::InvalidMergeInput);
        }

        if let BranchChangeType::AddMember = self.change_type {
            return Err(ArtError::InvalidMergeInput);
        }

        art.upstream_art.merge_by_marker(
            &self.public_keys,
            &self.node_index.get_path()?,
            &mut art.marker_tree,
        )
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
            return Err(ArtError::InvalidMergeInput);
        }

        let merge_key = art.marker_tree.data;
        art.upstream_art.public_art.merge_by_marker(
            &self.public_keys,
            &self.node_index.get_path()?,
            &mut art.marker_tree,
        )?;
        let updated_secrets = art.get_updated_secrets(self)?;
        art.update_secrets(&updated_secrets, merge_key)?;

        Ok(())
    }
}

impl<G, R> ApplicableChange<PrivateZeroArt<G, R>> for PrivateBranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<(), ArtError> {
        if let BranchChangeType::AddMember = &self.branch_change.change_type {
            if art.marker_tree.data {
                return Err(ArtError::InvalidMergeInput);
            }

            let mut path = self.branch_change.node_index.get_path()?;
            let last_direction = path.pop().ok_or(ArtError::NoChanges)?;

            let parent_art_node = art.upstream_art.get_mut_node_at(&path)?;
            let parent_marker_node = art.marker_tree.get_mut_node(&path)?;

            // if true, then add member was with extension (instead of replacement).
            if parent_art_node.get_child(last_direction).is_none() {
                // The last bit of direction will not be used in proof verification, so check it
                // manually. New node must be added to the right.
                if !matches!(last_direction, Direction::Right) {
                    return Err(ArtError::InvalidUpdateData);
                }

                PrivateZeroArt::<G, R>::extend_marker_node(parent_marker_node, true);
                parent_art_node.extend(ArtNode::new_leaf(
                    *self
                        .branch_change
                        .public_keys
                        .last()
                        .ok_or(ArtError::NoChanges)?,
                ));

                let path_index = NodeIndex::from(path);
                if art.upstream_art.node_index.is_subpath_of(&path_index)? {
                    // Change updates existing node index, so it will be extended to the left.
                    art.upstream_art.secrets.insert(
                        0,
                        art.upstream_art
                            .secrets
                            .first()
                            .ok_or(ArtError::EmptyArt)?
                            .clone(),
                    );
                    art.upstream_art.node_index.push(Direction::Left);
                }
            }
        }

        if self.branch_change.change_type == BranchChangeType::UpdateKey
            || art.base_art.node_index == self.branch_change.node_index
        {
            return self.inner_apply_own_key_update(art, self.secret);
        }

        let merge_key = art.marker_tree.data;
        art.upstream_art.public_art.merge_by_marker(
            &self.branch_change.public_keys,
            &self.branch_change.node_index.get_path()?,
            &mut art.marker_tree,
        )?;

        let target_leaf_status = match &self.branch_change.change_type {
            BranchChangeType::UpdateKey => Some(LeafStatus::Active),
            BranchChangeType::AddMember => None,
            BranchChangeType::RemoveMember => Some(LeafStatus::Blank),
            BranchChangeType::Leave => Some(LeafStatus::PendingRemoval),
        };
        if let Some(target_leaf_status) = target_leaf_status {
            art.upstream_art
                .get_mut_node_at(&self.branch_change.node_index.get_path()?)?
                .set_status(target_leaf_status)?;
        }

        let updated_secrets = art.get_updated_secrets(&self.branch_change)?;
        art.update_secrets(&updated_secrets, merge_key)?;

        Ok(())
    }
}
