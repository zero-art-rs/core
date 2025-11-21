use crate::art::ProverArtefacts;
use crate::art::{ArtUpdateOutput, PublicMergeData};
use crate::art::{PrivateArt, PublicArt};
use crate::art_node::{ArtNode, LeafStatus, TreeMethods};
use crate::changes::aggregations::{
    AggregationData, AggregationNode, AggregationNodeIterWithPath, ProverAggregationData,
    VerifierAggregationData,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::helper_tools::recompute_artefacts;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::iterable::Iterable;
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use tracing::error;
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};

/// Helper data type, which contains necessary data about aggregation. Can be used to update
/// state of other ART tree.
pub type AggregatedChange<G> = AggregationTree<AggregationData<G>>;

/// Helper data struct for proof verification.
pub(crate) type VerifierChangeAggregation<G> = AggregationTree<VerifierAggregationData<G>>;

/// General tree for Aggregation structures. Type `D` is a data type stored in the node of a tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "D: Serialize", deserialize = "D: Deserialize<'de>"))]
pub struct AggregationTree<D> {
    pub(crate) root: Option<AggregationNode<D>>,
}

impl<D> AggregationTree<D> {
    pub fn root(&self) -> Option<&AggregationNode<D>> {
        self.root.as_ref()
    }

    pub(crate) fn mut_root(&mut self) -> &mut Option<AggregationNode<D>> {
        &mut self.root
    }

    pub fn node_at(&self, path: &[Direction]) -> Option<&AggregationNode<D>> {
        let Some(mut target_node) = self.root.as_ref() else {
            return None;
        };

        for dir in path {
            let Some(child) = target_node.child(*dir) else {
                return None;
            };
            target_node = child;
        }

        Some(target_node)
    }

    pub fn mut_node_at(&mut self, path: &[Direction]) -> Option<&mut AggregationNode<D>> {
        let Some(mut target_node) = self.root.as_mut() else {
            return None;
        };

        for dir in path {
            let Some(child) = target_node.mut_child(*dir) else {
                return None;
            };
            target_node = child;
        }

        Some(target_node)
    }
}

impl<G> AggregationNode<PublicMergeData<G>>
where
    G: AffineRepr,
{
    pub(crate) fn preview_public_key(&self) -> G {
        // if self.data.strong_key().is_none() && self.data.weak_key().is_none() {
        //     return Err(ArtError::ArtLogic);
        // }

        self.data
            .strong_key()
            .get_or_insert_with(G::zero)
            .add(*self.data.weak_key().get_or_insert_with(G::zero))
            .into_affine()
    }

    pub fn status(&self) -> Option<LeafStatus> {
        self.data.status()
    }

    pub(crate) fn update_public_key(&mut self, public_key: G, weak_only: bool) {
        if !weak_only && self.data.strong_key().is_none() {
            *self.data.mut_strong_key() = Some(public_key);
        } else {
            let weak_key = self.data.mut_weak_key().get_or_insert_with(G::zero);
            *self.data.mut_weak_key() = Some(weak_key.add(public_key).into_affine());
        }
    }
}

impl<G> AggregationTree<PublicMergeData<G>>
where
    G: AffineRepr,
{
    /// Update branch and return the last node updated.
    pub(crate) fn add_branch_keys(
        &mut self,
        public_keys: &[G],
        path: &[Direction],
        weak_only: bool,
        weight_change: Option<bool>,
    ) -> Result<&mut AggregationNode<PublicMergeData<G>>, ArtError> {
        if public_keys.len() != path.len() + 1 {
            error!(
                "Invalid size for pk path ({}) and direction path: ({})",
                public_keys.len(),
                path.len()
            );
            return Err(ArtError::InvalidBranchChange);
        }

        let mut current_node = self.root.get_or_insert_default();

        let root_pk = *public_keys.first().ok_or(ArtError::NoChanges)?;
        current_node.update_public_key(root_pk, weak_only);
        if let Some(weight_change) = weight_change {
            current_node.data.update_weight_change(weight_change);
        }

        if public_keys.len() <= 1 {
            return Ok(current_node);
        }

        for (dir, pk) in path.iter().zip(public_keys[1..].iter()) {
            current_node = current_node.mut_child(*dir).get_or_insert_default();

            current_node.update_public_key(*pk, weak_only);
            if let Some(weight_change) = weight_change {
                current_node.data.update_weight_change(weight_change);
            }
        }

        Ok(current_node)
    }
}

// impl<G> AggregationTree<AggregationData<G>>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     /// Update public art public keys with ones provided in the `verifier_aggregation` tree.
//     pub fn add_co_path(
//         &self,
//         art: &PublicArt<G>,
//     ) -> Result<VerifierChangeAggregation<G>, ArtError> {
//         let agg_root = match self.root() {
//             Some(root) => root,
//             None => return Err(ArtError::NoChanges),
//         };
//
//         let mut resulting_aggregation_root =
//             AggregationNode::<VerifierAggregationData<G>>::try_from(agg_root)?;
//
//         for (_, path) in AggregationNodeIterWithPath::new(agg_root).skip(1) {
//             let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
//             let last_direction = parent_path.pop().ok_or(ArtError::NoChanges)?;
//
//             let aggregation_parent = path
//                 .last()
//                 .ok_or(ArtError::NoChanges)
//                 .map(|(node, _)| *node)?;
//
//             let resulting_target_node = resulting_aggregation_root
//                 .mut_node(&parent_path)?
//                 .mut_node(&[last_direction])?;
//
//             // Update co-path
//             let pk = if let Ok(co_leaf) = aggregation_parent.node(&[last_direction.other()]) {
//                 // Retrieve co-path from the aggregation
//                 co_leaf.data.public_key
//             } else if let Ok(parent) = art.node(&NodeIndex::Direction(parent_path.clone()))
//                 && let Some(other_child) = parent.child(last_direction.other())
//             {
//                 // Try to retrieve Co-path from the original ART
//                 other_child.public_key()
//             } else {
//                 // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
//                 let mut path = parent_path.clone();
//                 path.push(last_direction.other());
//                 Self::get_last_public_key_on_path(art, agg_root, &path)?
//             };
//             resulting_target_node.data.co_public_key = Some(pk);
//         }
//
//         Ok(AggregationTree {
//             root: Some(resulting_aggregation_root),
//         })
//     }
//
//     /// Retrieve the last public key on given `path`, by applying required changes from the
//     /// `aggregation`.
//     pub(crate) fn get_last_public_key_on_path(
//         art: &PublicArt<G>,
//         aggregation: &AggregationNode<AggregationData<G>>,
//         path: &[Direction],
//     ) -> Result<G, ArtError> {
//         let mut leaf_public_key = art.get_root().public_key();
//
//         let mut current_art_node = Some(art.get_root());
//         let mut current_agg_node = Some(aggregation);
//         for (i, dir) in path.iter().enumerate() {
//             // Retrieve leaf public key from art
//             if let Some(art_node) = current_art_node {
//                 if let Some(node) = art_node.child(*dir) {
//                     if let ArtNode::Leaf { public_key, .. } = node {
//                         leaf_public_key = *public_key;
//                     }
//
//                     current_art_node = Some(node);
//                 } else {
//                     current_art_node = None;
//                 }
//             }
//
//             // Retrieve leaf public key updates form aggregation
//             if let Some(agg_node) = current_agg_node {
//                 if let Some(node) = agg_node.child(*dir) {
//                     for change_type in &node.data.change_type {
//                         match change_type {
//                             BranchChangeTypeHint::RemoveMember { pk: blank_pk, .. } => {
//                                 leaf_public_key = *blank_pk
//                             }
//                             BranchChangeTypeHint::AddMember { pk, ext_pk, .. } => {
//                                 if let Some(replacement_pk) = ext_pk {
//                                     match path.get(i + 1) {
//                                         Some(Direction::Right) => leaf_public_key = *pk,
//                                         Some(Direction::Left) => {}
//                                         None => leaf_public_key = *replacement_pk,
//                                     }
//                                 } else {
//                                     leaf_public_key = *pk;
//                                 }
//                             }
//                             BranchChangeTypeHint::UpdateKey { pk } => leaf_public_key = *pk,
//                             BranchChangeTypeHint::Leave { pk } => leaf_public_key = *pk,
//                         }
//                     }
//
//                     current_agg_node = Some(node);
//                 } else {
//                     current_agg_node = None;
//                 }
//             }
//         }
//
//         Ok(leaf_public_key)
//     }
//
//     pub(crate) fn update_public_art(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
//         let agg_root = match self.root() {
//             Some(root) => root,
//             None => return Err(ArtError::NoChanges),
//         };
//
//         for (item, path) in AggregationNodeIterWithPath::new(agg_root) {
//             let item_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
//
//             for change_type in &item.data.change_type {
//                 match change_type {
//                     BranchChangeTypeHint::RemoveMember {
//                         pk: blank_pk,
//                         merge,
//                     } => {
//                         if !*merge {
//                             art.update_weight(&item_path, false)?;
//                         }
//
//                         self.update_public_art_upper_branch(&item_path, art, false, 0)?;
//
//                         let corresponding_item =
//                             art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
//                         corresponding_item.set_status(LeafStatus::Blank)?;
//                         corresponding_item.set_public_key(*blank_pk);
//                     }
//                     BranchChangeTypeHint::AddMember { pk, ext_pk } => {
//                         art.update_weight(&item_path, true)?;
//
//                         art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?
//                             .extend_or_replace(ArtNode::new_leaf(*pk))?;
//
//                         let mut parent_path = item_path.clone();
//                         parent_path.pop();
//                         self.update_public_art_upper_branch(&parent_path, art, false, 0)?;
//
//                         let corresponding_item =
//                             art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
//                         if let Some(ext_pk) = ext_pk {
//                             corresponding_item.set_public_key(*ext_pk)
//                         }
//                     }
//                     BranchChangeTypeHint::UpdateKey { pk } => {
//                         self.update_public_art_upper_branch(&item_path, art, false, 0)?;
//
//                         let corresponding_item =
//                             art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
//                         corresponding_item.set_public_key(*pk);
//                     }
//                     BranchChangeTypeHint::Leave { pk } => {
//                         self.update_public_art_upper_branch(&item_path, art, false, 0)?;
//
//                         let corresponding_item =
//                             art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
//                         corresponding_item.set_status(LeafStatus::PendingRemoval)?;
//                         corresponding_item.set_public_key(*pk);
//                     }
//                 }
//             }
//         }
//
//         Ok(())
//     }
//
//     /// Update art by applying changes from the provided aggregation. Also updates `path_secrets`
//     /// and `node_index`.
//     pub(crate) fn update_private_art(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
//         self.update_public_art(&mut art.public_art)?;
//
//         // art.update_node_index()?;
//         art.update_node_index_and_extend_secrets()?;
//         self.update_path_secrets_with_aggregation_tree(art)?;
//
//         Ok(())
//     }
//
//     /// Allows to update public keys on the given `path` with public keys provided in
//     /// `verifier_aggregation`. Also, it allows to skip and not update first `skip` nodes on path.
//     fn update_public_art_upper_branch(
//         &self,
//         path: &[Direction],
//         art: &mut PublicArt<G>,
//         append_changes: bool,
//         skip: usize,
//     ) -> Result<(), ArtError> {
//         let mut current_agg_node = match self.root() {
//             Some(root) => root,
//             None => return Err(ArtError::NoChanges),
//         };
//
//         // Update root
//         if skip == 0 {
//             match append_changes {
//                 true => art
//                     .get_mut_root()
//                     .merge_public_key(current_agg_node.data.public_key),
//                 false => art
//                     .get_mut_root()
//                     .set_public_key(current_agg_node.data.public_key),
//             }
//         }
//
//         for i in 1..skip {
//             current_agg_node = current_agg_node
//                 .child(path[i])
//                 .ok_or(ArtError::InvalidAggregation)?;
//         }
//
//         for i in skip..path.len() {
//             current_agg_node = current_agg_node
//                 .child(path[i + skip])
//                 .ok_or(ArtError::InvalidAggregation)?;
//             let target_node = art.mut_node_at(&path[0..i + 1])?;
//
//             match append_changes {
//                 true => target_node.merge_public_key(current_agg_node.data.public_key),
//                 false => target_node.set_public_key(current_agg_node.data.public_key),
//             }
//         }
//
//         Ok(())
//     }
//
//     /// Similar to `update_path_secrets`, but instead of NodeIndex `other` provided by change,
//     /// takes the ChangeAggregation tree.
//     fn update_path_secrets_with_aggregation_tree(
//         &self,
//         art: &mut PrivateArt<G>,
//     ) -> Result<(), ArtError> {
//         let path_secrets = art.secrets.clone();
//
//         let agg_root = match self.root() {
//             Some(root) => root,
//             None => return Err(ArtError::NoChanges),
//         };
//
//         if path_secrets.is_empty() {
//             return Err(ArtError::EmptyArt);
//         }
//
//         if agg_root.contains(&art.get_node_index().get_path()?) {
//             return Err(ArtError::InvalidInput);
//         }
//
//         // It is a partial update of the path.
//         let node_path = art.get_node_index().get_path()?;
//         let mut intersection = agg_root.get_intersection(&node_path);
//
//         let mut partial_co_path = Vec::new();
//         let mut current_art_node = art.get_root();
//         let mut current_agg_node = agg_root;
//         let mut add_member_counter = current_agg_node
//             .data
//             .change_type
//             .iter()
//             .filter(|change| matches!(change, BranchChangeTypeHint::AddMember { .. }))
//             .count();
//         for dir in &intersection {
//             partial_co_path.push(
//                 current_art_node
//                     .child(dir.other())
//                     .ok_or(ArtError::InvalidInput)?
//                     .public_key(),
//             );
//
//             current_art_node = current_art_node.child(*dir).ok_or(ArtError::InvalidInput)?;
//             current_agg_node = current_agg_node
//                 .child(*dir)
//                 .ok_or(ArtError::PathNotExists)?;
//
//             add_member_counter += current_agg_node
//                 .data
//                 .change_type
//                 .iter()
//                 .filter(|change| matches!(change, BranchChangeTypeHint::AddMember { .. }))
//                 .count();
//         }
//
//         intersection.push(node_path[intersection.len()].other());
//         partial_co_path.push(agg_root.node(&intersection)?.data.public_key);
//         partial_co_path.reverse();
//
//         // Compute path_secrets for aggregation.
//         let resulting_path_secrets_len = art.secrets.len() + add_member_counter;
//         let index = resulting_path_secrets_len - partial_co_path.len() - 1;
//         let level_sk = art.secrets[index];
//
//         let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, &partial_co_path)?;
//
//         let mut new_path_secrets = art.secrets.clone();
//         for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
//             new_path_secrets[i] = *sk;
//         }
//
//         // Update node `path_secrets`
//         art.secrets = new_path_secrets;
//
//         Ok(())
//     }
// }
//
// impl<G> AggregationTree<ProverAggregationData<G>>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     pub(crate) fn extend<R>(
//         &mut self,
//         rng: &mut R,
//         changes: &BranchChange<G>,
//         artefacts: &ProverArtefacts<G>,
//         change_hint: BranchChangeTypeHint<G>,
//     ) -> Result<(), ArtError>
//     where
//         R: Rng + ?Sized,
//     {
//         let root = self
//             .root
//             .get_or_insert_with(AggregationNode::<ProverAggregationData<G>>::default);
//
//         root.extend(rng, changes, artefacts, change_hint)
//     }
//
//     /// Updates art by applying changes. Also updates path_secrets and node_index.
//     pub(crate) fn inner_update_key<R>(
//         &mut self,
//         new_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//         rng: &mut R,
//     ) -> Result<ArtUpdateOutput<G>, ArtError>
//     where
//         R: Rng + ?Sized,
//     {
//         let index = art.get_node_index().clone();
//         let (tk, change, artefacts) = art.private_update_node_key(&index, new_secret_key, false)?;
//
//         self.extend(
//             rng,
//             &change,
//             &artefacts,
//             BranchChangeTypeHint::UpdateKey {
//                 pk: G::generator().mul(new_secret_key).into_affine(),
//             },
//         )?;
//
//         Ok((tk, change, artefacts))
//     }
//
//     pub(crate) fn inner_remove_member<R>(
//         &mut self,
//         path: &[Direction],
//         temporary_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//         rng: &mut R,
//     ) -> Result<ArtUpdateOutput<G>, ArtError>
//     where
//         R: Rng + ?Sized,
//     {
//         let append_changes = matches!(art.node_at(path)?.status(), Some(LeafStatus::Blank));
//
//         if append_changes {
//             return Err(ArtError::InvalidMergeInput);
//         }
//
//         let index = NodeIndex::from(path.to_vec());
//         let (tk, mut change, artefacts) =
//             art.private_update_node_key(&index, temporary_secret_key, append_changes)?;
//         change.change_type = BranchChangeType::RemoveMember;
//
//         self.extend(
//             rng,
//             &change,
//             &artefacts,
//             BranchChangeTypeHint::RemoveMember {
//                 pk: G::generator().mul(temporary_secret_key).into_affine(),
//                 merge: append_changes,
//             },
//         )?;
//
//         art.mut_node_at(path)?.set_status(LeafStatus::Blank)?;
//
//         if !append_changes {
//             art.public_art.update_weight(path, false)?;
//         }
//
//         Ok((tk, change, artefacts))
//     }
//
//     pub(crate) fn inner_add_member<R>(
//         &mut self,
//         secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//         rng: &mut R,
//     ) -> Result<ArtUpdateOutput<G>, ArtError>
//     where
//         R: Rng + ?Sized,
//     {
//         let path = art.get_public_art().find_place_for_new_node()?;
//
//         let hint = matches!(
//             art.get_public_art()
//                 .get_node(&NodeIndex::Direction(path.to_vec()))?
//                 .get_status(),
//             Some(LeafStatus::Active)
//         );
//
//         let (tk, mut changes, artefacts) = art.private_add_node(secret_key)?;
//         changes.change_type = BranchChangeType::AddMember;
//
//         let ext_pk = match hint {
//             true => Some(
//                 art.get_public_art()
//                     .get_node(&NodeIndex::Direction(path.to_vec()))?
//                     .get_public_key(),
//             ),
//             false => None,
//         };
//
//         self.extend(
//             rng,
//             &changes,
//             &artefacts,
//             BranchChangeTypeHint::AddMember {
//                 pk: G::generator().mul(secret_key).into_affine(),
//                 ext_pk,
//             },
//         )?;
//
//         Ok((tk, changes, artefacts))
//     }
//
//     pub(crate) fn inner_leave_group<R>(
//         &mut self,
//         new_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//         rng: &mut R,
//     ) -> Result<ArtUpdateOutput<G>, ArtError>
//     where
//         R: Rng + ?Sized,
//     {
//         let index = art.get_node_index().clone();
//         let (tk, mut change, artefacts) =
//             art.private_update_node_key(&index, new_secret_key, false)?;
//         change.change_type = BranchChangeType::Leave;
//
//         self.extend(
//             rng,
//             &change,
//             &artefacts,
//             BranchChangeTypeHint::Leave {
//                 pk: G::generator().mul(new_secret_key).into_affine(),
//             },
//         )?;
//
//         art.get_mut_node(&index)?
//             .set_status(LeafStatus::PendingRemoval)?;
//
//         Ok((tk, change, artefacts))
//     }
// }

impl<'a, D1, D2> TryFrom<&'a AggregationTree<D1>> for AggregationTree<D2>
where
    D1: Clone + Default,
    D2: From<D1> + Clone + Default,
    AggregationNode<D2>: TryFrom<&'a AggregationNode<D1>, Error = ArtError>,
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationTree<D1>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(AggregationTree::default()),
            Some(root) => Ok(AggregationTree {
                root: Some(AggregationNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D, G> TryFrom<&'a AggregationTree<D>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
    D: Clone + Default,
    Self: TryFrom<&'a AggregationNode<D>, Error = ArtError>,
{
    type Error = <Self as TryFrom<&'a AggregationNode<D>>>::Error;

    fn try_from(value: &'a AggregationTree<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}

impl<D> Display for AggregationTree<D>
where
    D: Clone + Display + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.root() {
            Some(root) => write!(f, "{}", root),
            None => write!(f, "Empty aggregation."),
        }
    }
}

impl<'a, D, G> TryFrom<&'a AggregationTree<D>> for ProverAggregationTree<G>
where
    G: AffineRepr,
    D: Clone + Default,
    Self: TryFrom<&'a AggregationNode<D>, Error = ArtError>,
{
    type Error = <Self as TryFrom<&'a AggregationNode<D>>>::Error;

    fn try_from(value: &'a AggregationTree<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use crate::art::PrivateArt;
//     use crate::art::{AggregationContext, ArtAdvancedOps, PrivateZeroArt};
//     use crate::changes::aggregations::AggregatedChange;
//     use crate::test_helper_tools::init_tracing;
//     use ark_std::UniformRand;
//     use ark_std::rand::prelude::StdRng;
//     use ark_std::rand::{SeedableRng, thread_rng};
//     use cortado::{CortadoAffine, Fr};
//
//     #[test]
//     fn test_aggregation_serialization() {
//         init_tracing();
//
//         let mut rng = StdRng::seed_from_u64(0);
//
//         let user0_rng = Box::new(thread_rng());
//         let mut user0 = PrivateZeroArt::new(
//             PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap(),
//             user0_rng,
//         )
//         .unwrap();
//
//         let mut agg = AggregationContext::new(user0.get_base_art().clone(), Box::new(thread_rng()));
//         for _ in 0..8 {
//             agg.add_member(Fr::rand(&mut rng)).unwrap();
//         }
//
//         let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();
//
//         let bytes = postcard::to_allocvec(&plain_agg).unwrap();
//         let retrieved_agg: AggregatedChange<CortadoAffine> = postcard::from_bytes(&bytes).unwrap();
//
//         assert_eq!(retrieved_agg, plain_agg);
//     }
// }
