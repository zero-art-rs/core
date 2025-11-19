// use crate::art::{
//     AggregationContext, PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt,
//     handle_potential_art_node_extension_on_add_member,
//     handle_potential_marker_tree_node_extension_on_add_member, update_secrets_if_need,
// };
// use crate::art_node::{LeafStatus, TreeMethods};
// use crate::changes::aggregations::{AggregatedChange, AggregationNode};
// use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
// use crate::helper_tools;
// use crate::helper_tools::compute_merge_bound;
// use ark_ec::AffineRepr;
// use ark_ff::PrimeField;
// use ark_std::rand::Rng;
// use cortado::CortadoAffine;
// use std::mem;

/// A trait for ART change that can be applied to the ART.
///
/// This trait represents an ability of change to update ART tree `art` (instance of type `T`).
///
/// # Type Parameters
/// * `T` – The type of the ART tree type being updated.
pub trait ApplicableChange<T, R> {
    /// Apply a change to the provided `art`. May return some auxiliary data of type `R`.
    fn apply(&self, art: &mut T) -> Result<R, ArtError>;
}

// impl<G> ApplicableChange<PublicArt<G>, ()> for BranchChange<G>
// where
//     G: AffineRepr,
// {
//     fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
//         if let BranchChangeType::RemoveMember = self.change_type
//             && let Some(LeafStatus::Blank) = art.node(&self.node_index)?.status()
//         {
//             art.update_with_options(self, true, false)
//         } else {
//             art.update_with_options(self, false, true)
//         }
//     }
// }
//
// impl<G> ApplicableChange<PrivateArt<G>, ()> for BranchChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
//         if let BranchChangeType::RemoveMember = self.change_type
//             && matches!(
//                 art.public_art.node(&self.node_index)?.status(),
//                 Some(LeafStatus::Blank)
//             )
//         {
//             art.update_private_art_with_options(self, true, false)
//         } else {
//             art.update_private_art_with_options(self, false, true)
//         }
//     }
// }
//
// impl<G> ApplicableChange<PublicArt<G>, ()> for AggregatedChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
//         self.update_public_art(art)
//     }
// }
//
// impl<G> ApplicableChange<PrivateArt<G>, ()> for AggregatedChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
//         self.update_private_art(art)
//     }
// }
//
// impl ApplicableChange<PublicZeroArt<CortadoAffine>, ()> for AggregatedChange<CortadoAffine> {
//     fn apply(&self, art: &mut PublicZeroArt<CortadoAffine>) -> Result<(), ArtError> {
//         if art.marker_tree.data {
//             return Err(ArtError::InapplicableAggregation);
//         }
//
//         self.update_public_art(&mut art.upstream_art)?;
//         art.commit()?;
//         art.marker_tree = AggregationNode::<bool>::try_from(art.base_art.get_root())?;
//
//         Ok(())
//     }
// }
//
// impl<G, R> ApplicableChange<PrivateZeroArt<G, R>, ()> for AggregatedChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<(), ArtError> {
//         if art.marker_tree.data {
//             return Err(ArtError::InapplicableAggregation);
//         }
//
//         self.update_private_art(&mut art.upstream_art)?;
//         art.commit()?;
//         art.marker_tree = AggregationNode::<bool>::try_from(art.base_art.get_root())?;
//
//         Ok(())
//     }
// }
//
// impl<G, R1, R2> ApplicableChange<PrivateZeroArt<G, R1>, ()>
//     for AggregationContext<PrivateArt<G>, G, R2>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R1: Rng + ?Sized,
//     R2: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateZeroArt<G, R1>) -> Result<(), ArtError> {
//         if art.marker_tree.data {
//             return Err(ArtError::InapplicableAggregation);
//         }
//
//         art.upstream_art = self.operation_tree.clone();
//         art.commit()?;
//         art.marker_tree = AggregationNode::<bool>::try_from(art.base_art.get_root())?;
//
//         Ok(())
//     }
// }
//
// impl<G, R> ApplicableChange<PrivateArt<G>, ()> for AggregationContext<PrivateArt<G>, G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
//         let _ = mem::replace(art, self.operation_tree.clone());
//
//         Ok(())
//     }
// }
//
// impl<G> ApplicableChange<PublicZeroArt<G>, ()> for BranchChange<G>
// where
//     G: AffineRepr,
// {
//     fn apply(&self, art: &mut PublicZeroArt<G>) -> Result<(), ArtError> {
//         let mut marker_tree = art.marker_tree.clone();
//         let mut upstream_art = art.upstream_art.clone();
//
//         let mut target_path = self.node_index.get_path()?;
//         let last_direction = target_path.pop().ok_or(ArtError::NoChanges)?;
//
//         if let BranchChangeType::AddMember = &self.change_type {
//             if marker_tree.data {
//                 return Err(ArtError::InvalidMergeInput);
//             }
//
//             let art_tree_increased = handle_potential_art_node_extension_on_add_member(
//                 &mut upstream_art,
//                 &target_path,
//                 last_direction,
//             )?;
//
//             handle_potential_marker_tree_node_extension_on_add_member(
//                 &mut marker_tree,
//                 &target_path,
//                 last_direction,
//             )?;
//
//             if art_tree_increased {
//                 upstream_art.update_weight(&target_path, true)?;
//             }
//         }
//
//         if let BranchChangeType::RemoveMember = &self.change_type {
//             if matches!(
//                 upstream_art.node(&self.node_index)?.status(),
//                 Some(LeafStatus::Blank)
//             ) {
//                 art.stashed_confirm_removals.push(self.clone());
//                 return Ok(());
//             }
//
//             upstream_art.update_weight(&target_path, false)?;
//         }
//
//         if let BranchChangeType::Leave = &self.change_type {
//             upstream_art.update_weight(&target_path, false)?;
//         }
//
//         upstream_art.merge_by_marker(
//             &self.public_keys,
//             &self.node_index.get_path()?,
//             &mut marker_tree,
//         )?;
//
//         helper_tools::change_leaf_status_by_change_type(
//             upstream_art.get_mut_node_at(&self.node_index.get_path()?)?,
//             &self.change_type,
//         )?;
//
//         art.marker_tree = marker_tree;
//         art.upstream_art = upstream_art;
//
//         Ok(())
//     }
// }
//
// impl<G, R> ApplicableChange<PrivateZeroArt<G, R>, G::ScalarField> for BranchChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<G::ScalarField, ArtError> {
//         let mut marker_tree = art.marker_tree.clone();
//         let mut upstream_art = art.upstream_art.clone();
//
//         upstream_art.verify_change_applicability(self)?;
//         let mut target_path = self.node_index.get_path()?;
//         let last_direction = target_path.pop().ok_or(ArtError::NoChanges)?;
//
//         if let BranchChangeType::AddMember = &self.change_type {
//             if marker_tree.data {
//                 return Err(ArtError::InvalidMergeInput);
//             }
//
//             let art_tree_increased = handle_potential_art_node_extension_on_add_member(
//                 &mut upstream_art.public_art,
//                 &target_path,
//                 last_direction,
//             )?;
//
//             let _ = handle_potential_marker_tree_node_extension_on_add_member(
//                 &mut marker_tree,
//                 &target_path,
//                 last_direction,
//             )?;
//
//             if art_tree_increased {
//                 update_secrets_if_need(&mut upstream_art, &target_path)?;
//                 upstream_art.public_art.update_weight(&target_path, true)?;
//             }
//         }
//
//         if let BranchChangeType::RemoveMember = &self.change_type {
//             if matches!(
//                 upstream_art.node(&self.node_index)?.status(),
//                 Some(LeafStatus::Blank)
//             ) {
//                 art.stashed_confirm_removals.push(self.clone());
//                 let updated_secrets = art.get_updated_secrets(self)?;
//                 return Ok(*updated_secrets.last().ok_or(ArtError::EmptyArt)?);
//             }
//
//             upstream_art.public_art.update_weight(&target_path, false)?;
//         }
//
//         if let BranchChangeType::Leave = &self.change_type {
//             upstream_art.public_art.update_weight(&target_path, false)?;
//         }
//
//         let merge_bound = compute_merge_bound(&marker_tree, &self.node_index.get_path()?)?;
//
//         upstream_art.public_art.merge_by_marker(
//             &self.public_keys,
//             &self.node_index.get_path()?,
//             &mut marker_tree,
//         )?;
//
//         helper_tools::change_leaf_status_by_change_type(
//             upstream_art.get_mut_node_at(&self.node_index.get_path()?)?,
//             &self.change_type,
//         )?;
//
//         let updated_secrets = art.get_updated_secrets(self)?;
//         upstream_art.update_secrets_with_merge_bound(&updated_secrets, merge_bound)?;
//
//         let tk = *updated_secrets.last().ok_or(ArtError::EmptyArt)?;
//
//         art.marker_tree = marker_tree;
//         art.upstream_art = upstream_art;
//
//         Ok(tk)
//     }
// }
//
// impl<G> ApplicableChange<PublicZeroArt<G>, ()> for PrivateBranchChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn apply(&self, art: &mut PublicZeroArt<G>) -> Result<(), ArtError> {
//         self.branch_change.apply(art)
//     }
// }
//
// impl<G, R> ApplicableChange<PrivateZeroArt<G, R>, G::ScalarField> for PrivateBranchChange<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<G::ScalarField, ArtError> {
//         if self.branch_change.change_type == BranchChangeType::UpdateKey
//             && art.base_art.node_index == self.branch_change.node_index
//         {
//             return self.leaf_secret.apply(art);
//         }
//
//         self.branch_change.apply(art)
//     }
// }
//
// impl<G, R, S> ApplicableChange<PrivateZeroArt<G, R>, G::ScalarField> for S
// where
//     S: PrimeField,
//     G: AffineRepr<ScalarField = S>,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn apply(&self, art: &mut PrivateZeroArt<G, R>) -> Result<G::ScalarField, ArtError> {
//         helper_tools::inner_apply_own_key_update(art, *self)
//     }
// }
