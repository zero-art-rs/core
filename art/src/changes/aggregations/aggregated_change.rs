use crate::art::{PublicArt, PublicMergeData};
use crate::art_node::{ArtNode, LeafStatus};
use crate::changes::aggregations::{
    AggregationData, BinaryTreeNode, AggregationNodeIterWithPath, VerifierAggregationData,
};
use crate::changes::branch_change::{
    BranchChange, BranchChangeType, BranchChangeTypeHint, PrivateBranchChange,
};
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
pub type AggregatedChange<G> = BinaryTree<AggregationData<G>>;

/// Helper structure to apply aggregations with own key update correctly.
pub struct PrivateAggregatedChange<G: AffineRepr>(G::ScalarField, AggregatedChange<G>);

/// Helper data struct for proof verification.
pub(crate) type VerifierChangeAggregation<G> = BinaryTree<VerifierAggregationData<G>>;

/// General tree for Aggregation structures. Type `D` is a data type stored in the node of a tree.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound(serialize = "D: Serialize", deserialize = "D: Deserialize<'de>"))]
pub struct BinaryTree<D> {
    pub(crate) root: Option<BinaryTreeNode<D>>,
}

impl<D> BinaryTree<D> {
    pub fn new(root: Option<BinaryTreeNode<D>>) -> Self {
        Self { root }
    }

    pub fn root(&self) -> Option<&BinaryTreeNode<D>> {
        self.root.as_ref()
    }

    pub(crate) fn mut_root(&mut self) -> &mut Option<BinaryTreeNode<D>> {
        &mut self.root
    }

    pub fn node_at(&self, path: &[Direction]) -> Option<&BinaryTreeNode<D>> {
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

    pub fn mut_node_at(&mut self, path: &[Direction]) -> Option<&mut BinaryTreeNode<D>> {
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

impl<G: AffineRepr> PrivateAggregatedChange<G> {
    pub fn new(sk: G::ScalarField, change: AggregatedChange<G>) -> Self {
        Self(sk, change)
    }

    pub fn change(&self) -> &AggregatedChange<G> {
        &self.1
    }

    pub fn key(&self) -> G::ScalarField {
        self.0
    }
}

impl<G> BinaryTreeNode<PublicMergeData<G>>
where
    G: AffineRepr,
{
    pub(crate) fn preview_public_key(&self) -> G {
        // if self.data.strong_key().is_none() && self.data.weak_key().is_none() {
        //     return Err(ArtError::ArtLogic);
        // }

        self.data
            .strong_key
            .clone()
            .get_or_insert_with(G::zero)
            .add(*self.data.weak_key.clone().get_or_insert_with(G::zero))
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
        self.data.status
    }

    pub(crate) fn update_public_key(&mut self, public_key: G, weak_only: bool) {
        self.data.update_public_key(public_key, weak_only);
    }
}

impl<G> BinaryTree<PublicMergeData<G>>
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
    ) -> Result<&mut BinaryTreeNode<PublicMergeData<G>>, ArtError> {
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

impl<'a, D1, D2> TryFrom<&'a BinaryTree<D1>> for BinaryTree<D2>
where
    D1: Clone + Default,
    D2: From<D1> + Clone + Default,
    BinaryTreeNode<D2>: TryFrom<&'a BinaryTreeNode<D1>, Error = ArtError>,
{
    type Error = ArtError;

    fn try_from(value: &'a BinaryTree<D1>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(BinaryTree::default()),
            Some(root) => Ok(BinaryTree {
                root: Some(BinaryTreeNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D, G> TryFrom<&'a BinaryTree<D>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
    D: Clone + Default,
    Self: TryFrom<&'a BinaryTreeNode<D>, Error = ArtError>,
{
    type Error = <Self as TryFrom<&'a BinaryTreeNode<D>>>::Error;

    fn try_from(value: &'a BinaryTree<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}

impl<D> Display for BinaryTree<D>
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

impl<'a, D, G> TryFrom<&'a BinaryTree<D>> for ProverAggregationTree<G>
where
    G: AffineRepr,
    D: Clone + Default,
    Self: TryFrom<&'a BinaryTreeNode<D>, Error = ArtError>,
{
    type Error = <Self as TryFrom<&'a BinaryTreeNode<D>>>::Error;

    fn try_from(value: &'a BinaryTree<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}
