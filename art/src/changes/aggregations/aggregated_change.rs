use crate::art::{PublicArt, PublicMergeData};
use crate::art_node::{ArtNode, LeafStatus};
use crate::changes::aggregations::{
    AggregationData, AggregationNode, AggregationNodeIterWithPath, VerifierAggregationData,
};
use crate::changes::branch_change::{BranchChangeType, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::errors::ArtError::InapplicableAggregation;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use std::mem;
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

    pub fn update_weight(&mut self, path: &[Direction], increment: bool) -> Result<(), ArtError> {
        let mut current_node = self;
        current_node.data.update_weight_change(increment);
        for dir in path {
            current_node = current_node
                .mut_child(*dir)
                .as_mut()
                .ok_or(ArtError::PathNotExists)?;
            current_node.data.update_weight_change(increment);
        }

        Ok(())
    }

    pub fn apply(&mut self, change_type: &BranchChangeTypeHint<G>) -> Result<(), ArtError> {
        match change_type {
            BranchChangeTypeHint::AddMember { pk, ext_pk } => {
                if let Some(ext_pk) = ext_pk {
                    self.extend(
                        PublicMergeData::new(Some(*ext_pk), None, None, 0),
                        PublicMergeData::new(Some(*pk), None, Some(LeafStatus::Active), 0),
                    )?;
                } else {
                    self.data.strong_key = Some(*pk);
                    self.data.status = Some(LeafStatus::Active);
                    // self.data.update_status(LeafStatus::Active);
                    // self.data.update_public_key(*pk, false);
                }
            }
            BranchChangeTypeHint::RemoveMember { pk, merge } => {
                if *merge {
                    return Err(InapplicableAggregation);
                }

                // self.data.update_public_key(*pk, false);
                // self.data.update_status(LeafStatus::Blank);
                self.data.strong_key = Some(*pk);
                self.data.status = Some(LeafStatus::Blank);
            }
            BranchChangeTypeHint::UpdateKey { pk } => {
                // self.data.update_public_key(*pk, false);
                // self.data.update_status(LeafStatus::Active);
                self.data.strong_key = Some(*pk);
                self.data.status = Some(LeafStatus::Active);
            }
            BranchChangeTypeHint::Leave { pk } => {
                // self.data.update_public_key(*pk, false);
                // self.data.update_status(LeafStatus::PendingRemoval);
                self.data.strong_key = Some(*pk);
                self.data.status = Some(LeafStatus::PendingRemoval);
            }
        }

        Ok(())
    }

    /// Move self to the left. Update current node with `new_data`, and create new node on
    /// the right with `right_data`.
    pub fn extend(
        &mut self,
        new_data: PublicMergeData<G>,
        right_data: PublicMergeData<G>,
    ) -> Result<(), ArtError> {
        if !self.is_leaf() {
            return Err(ArtError::LeafOnly);
        }

        let old_data = mem::replace(&mut self.data, new_data);

        self.l = Some(Box::new(Self::new_leaf(old_data)));
        self.r = Some(Box::new(Self::new_leaf(right_data)));

        Ok(())
    }

    pub fn status(&self) -> Option<LeafStatus> {
        self.data.status()
    }

    pub(crate) fn update_public_key(&mut self, public_key: G, weak_only: bool) {
        self.data.update_public_key(public_key, weak_only);
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

        // Discard any last weight change
        if let Some(weight_change) = weight_change {
            current_node.data.update_weight_change(!weight_change);
        }

        Ok(current_node)
    }
}

impl<G> AggregationTree<AggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    /// Update public art public keys with ones provided in the `verifier_aggregation` tree.
    pub fn add_co_path(
        &self,
        art: &PublicArt<G>,
    ) -> Result<VerifierChangeAggregation<G>, ArtError> {
        let agg_root = match self.root() {
            Some(root) => root,
            None => return Err(ArtError::NoChanges),
        };

        let mut resulting_aggregation_root =
            AggregationNode::<VerifierAggregationData<G>>::try_from(agg_root)?;

        for (_, path) in AggregationNodeIterWithPath::new(agg_root).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let last_direction = parent_path.pop().ok_or(ArtError::NoChanges)?;

            let aggregation_parent = path
                .last()
                .ok_or(ArtError::NoChanges)
                .map(|(node, _)| *node)?;

            let resulting_target_node = resulting_aggregation_root
                .mut_node(&parent_path)?
                .mut_node(&[last_direction])?;

            // Update co-path
            let pk = if let Ok(co_leaf) = aggregation_parent.node_at(&[last_direction.other()]) {
                // Retrieve co-path from the aggregation
                co_leaf.data.public_key
            } else if let Ok(parent) = art.node(&NodeIndex::Direction(parent_path.clone()))
                && let Some(other_child) = parent.child(last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                other_child.public_key()
            } else {
                // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                Self::get_last_public_key_on_path(art, agg_root, &path)?
            };
            resulting_target_node.data.co_public_key = Some(pk);
        }

        Ok(AggregationTree {
            root: Some(resulting_aggregation_root),
        })
    }

    /// Retrieve the last public key on given `path`, by applying required changes from the
    /// `aggregation`.
    pub(crate) fn get_last_public_key_on_path(
        art: &PublicArt<G>,
        aggregation: &AggregationNode<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ArtError> {
        let mut leaf_public_key = art.root().public_key();

        let mut current_art_node = Some(art.root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            // Retrieve leaf public key from art
            if let Some(art_node) = current_art_node {
                if let Some(node) = art_node.child(*dir) {
                    if let ArtNode::Leaf { public_key, .. } = node {
                        leaf_public_key = *public_key;
                    }

                    current_art_node = Some(node);
                } else {
                    current_art_node = None;
                }
            }

            // Retrieve leaf public key updates form aggregation
            if let Some(agg_node) = current_agg_node {
                if let Some(node) = agg_node.child(*dir) {
                    for change_type in &node.data.change_type {
                        match change_type {
                            BranchChangeTypeHint::RemoveMember { pk: blank_pk, .. } => {
                                leaf_public_key = *blank_pk
                            }
                            BranchChangeTypeHint::AddMember { pk, ext_pk, .. } => {
                                if let Some(replacement_pk) = ext_pk {
                                    match path.get(i + 1) {
                                        Some(Direction::Right) => leaf_public_key = *pk,
                                        Some(Direction::Left) => {}
                                        None => leaf_public_key = *replacement_pk,
                                    }
                                } else {
                                    leaf_public_key = *pk;
                                }
                            }
                            BranchChangeTypeHint::UpdateKey { pk } => leaf_public_key = *pk,
                            BranchChangeTypeHint::Leave { pk } => leaf_public_key = *pk,
                        }
                    }

                    current_agg_node = Some(node);
                } else {
                    current_agg_node = None;
                }
            }
        }

        Ok(leaf_public_key)
    }
}

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
