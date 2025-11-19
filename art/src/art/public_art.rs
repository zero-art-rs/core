use crate::art::artefacts::VerifierArtefacts;
use crate::art::{ArtLevel, ArtUpdateOutput, ProverArtefacts};
use crate::art_node::{ArtNode, LeafIterWithPath, LeafStatus, NodeIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregationNode, AggregationNodeIterWithPath, AggregationTree, TreeIterHelper,
    TreeNodeIterWithPath,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
pub struct PublicMergeData<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    weak_key: Option<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    strong_key: Option<G>,
    status: Option<LeafStatus>,
}

impl<G> PublicMergeData<G>
where
    G: AffineRepr,
{
    pub fn weak_key(&self) -> Option<G> {
        self.weak_key
    }

    pub fn mut_weak_key(&mut self) -> &mut Option<G> {
        &mut self.weak_key
    }

    pub fn strong_key(&self) -> Option<G> {
        self.strong_key
    }

    pub fn mut_strong_key(&mut self) -> &mut Option<G> {
        &mut self.strong_key
    }

    pub fn status(&self) -> Option<LeafStatus> {
        self.status
    }

    pub fn mut_status(&mut self) -> &mut Option<LeafStatus> {
        &mut self.status
    }
}

/// Standard ART tree with public keys.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct PublicArt<G>
where
    G: AffineRepr,
{
    pub(crate) tree_root: ArtNode<G>,
    pub(crate) merge_tree: AggregationTree<PublicMergeData<G>>,
}

pub struct PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    public_art: &'a PublicArt<G>,
}

#[derive(Clone, Copy, Debug)]
pub enum ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    ArtNodeOnly {
        art_node: &'a ArtNode<G>,
    },
    MergeNodeOnly {
        merge_node: &'a AggregationNode<PublicMergeData<G>>,
    },
    Full {
        art_node: &'a ArtNode<G>,
        merge_node: &'a AggregationNode<PublicMergeData<G>>,
    },
}

impl<G> From<ArtNode<G>> for PublicArt<G>
where
    G: AffineRepr,
{
    fn from(tree_root: ArtNode<G>) -> Self {
        Self {
            tree_root,
            merge_tree: Default::default(),
        }
    }
}

impl<G> PublicArt<G>
where
    G: AffineRepr,
{
    pub fn apply<C, R>(&mut self, change: &C) -> Result<R, ArtError>
    where
        C: ApplicableChange<Self, R>,
    {
        change.apply(self)
    }

    pub fn commit(&mut self) -> Result<(), ArtError> {
        let Some(merge_tree) = mem::take(&mut self.merge_tree.root) else {
            return Ok(());
        };

        let art_reserve_copy = self.tree_root.clone();

        self.inner_commit(&merge_tree).inspect_err(|_| {
            self.merge_tree.root = Some(merge_tree);
            self.tree_root = art_reserve_copy;
        })
    }

    fn inner_commit(
        &mut self,
        merge_tree: &AggregationNode<PublicMergeData<G>>,
    ) -> Result<(), ArtError> {
        for (merge_node, path_data) in merge_tree.node_iter_with_path() {
            let path = path_data.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            let merge_data = &merge_node.data;
            let art_node = self.mut_root().mut_node_at(&path)?;

            if art_node.is_leaf() && !merge_node.is_leaf() {
                let public_key = merge_node
                    .child(Direction::Right)
                    .ok_or(ArtError::InvalidBranchChange)?
                    .preview_public_key();
                art_node.extend(ArtNode::new_leaf(public_key));
            } else {
                art_node.commit(Some(merge_data));
            }
        }

        Ok(())
    }

    pub fn find(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.root()) {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn find_leaf(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.root()) {
            if node.is_leaf() && node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn node(&self, index: &NodeIndex) -> Result<&ArtNode<G>, ArtError> {
        self.root().node(&index)
    }

    pub fn root(&self) -> &ArtNode<G> {
        &self.tree_root
    }

    pub(crate) fn mut_root(&mut self) -> &mut ArtNode<G> {
        &mut self.tree_root
    }

    pub fn preview(&self) -> PublicArtPreview<G> {
        PublicArtPreview { public_art: self }
    }

    pub(crate) fn post_process_change(
        &mut self,
        path: &Vec<Direction>,
        change_type: BranchChangeType,
    ) -> Result<(), ArtError> {
        match change_type {
            BranchChangeType::UpdateKey => {}
            BranchChangeType::AddMember => {
                let mut parent_path = path.clone();
                let last_path = parent_path.pop().ok_or(ArtError::InvalidBranchChange)?;

                let art_parent_node = self.node_at(&parent_path)?;
                let art_parent_node_pk = art_parent_node.public_key();
                let art_parent_node_is_leaf = art_parent_node.is_leaf();

                let merge_parent = self
                    .merge_tree
                    .mut_node_at(&parent_path)
                    .ok_or(ArtError::InvalidBranchChange)?;
                if art_parent_node_is_leaf {
                    let child = merge_parent.mut_child_or_default(last_path);
                    let Some(status) = child.data.mut_status() else {
                        return Err(ArtError::InvalidBranchChange);
                    };
                    *status = LeafStatus::Active
                } else {
                    if matches!(last_path, Direction::Left) {
                        return Err(ArtError::InvalidBranchChange);
                    }

                    let left_child = merge_parent.mut_child_or_default(Direction::Left);
                    *left_child.data.mut_strong_key() = Some(art_parent_node_pk);
                }
            }
            BranchChangeType::RemoveMember => {
                let target_node = self
                    .merge_tree
                    .mut_node_at(path)
                    .ok_or(ArtError::InvalidBranchChange)?;
                let Some(status) = target_node.data.mut_status() else {
                    return Err(ArtError::InvalidBranchChange);
                };
                *status = LeafStatus::Blank
            }
            BranchChangeType::Leave => {
                let target_node = self
                    .merge_tree
                    .mut_node_at(path)
                    .ok_or(ArtError::InvalidBranchChange)?;
                let Some(status) = target_node.data.mut_status() else {
                    return Err(ArtError::InvalidBranchChange);
                };
                if matches!(status, LeafStatus::Active) {
                    *status = LeafStatus::PendingRemoval
                }
            }
        }

        Ok(())
    }

    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn co_path(&self, path: &[Direction]) -> Result<Vec<G>, ArtError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.root();
        for direction in path {
            co_path_values.push(
                parent
                    .child(direction.other())
                    .ok_or(ArtError::InvalidInput)?
                    .public_key(),
            );
            parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let weak_only = if let BranchChangeType::RemoveMember = self.change_type {
            if let ArtNode::Leaf { status, .. } = art.node(&self.node_index)? {
                matches!(status, LeafStatus::Blank)
            } else {
                return Err(ArtError::InvalidBranchChange);
            }
        } else {
            false
        };

        let path = self.node_index.get_path()?;
        let merge_tree_reserve_copy = art.merge_tree.clone();

        if let Err(err) = art
            .merge_tree
            .add_branch_keys(&self.public_keys, &path, weak_only)
        {
            art.merge_tree = merge_tree_reserve_copy;
            return Err(err);
        }

        if let Err(err) = art.post_process_change(&path, self.change_type) {
            art.merge_tree = merge_tree_reserve_copy;
            return Err(err);
        }

        Ok(())
    }
}

impl<'a, G> PublicArtPreview<'a, G>
where
    G: AffineRepr,
{
    pub fn find(&self, public_key: G) -> Result<ArtNodePreview<G>, ArtError> {
        for (node, _) in TreeNodeIterWithPath::new(self.root()) {
            if node.public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn find_leaf(&self, public_key: G) -> Result<ArtNodePreview<G>, ArtError> {
        for (node, _) in TreeNodeIterWithPath::new(self.root()) {
            if let Some(art_node) = node.art_node()
                && art_node.is_leaf()
                && art_node.public_key().eq(&public_key)
            {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    pub fn node(&self, index: &NodeIndex) -> Result<ArtNodePreview<G>, ArtError> {
        let art_node = self.public_art.root().node(index).ok();

        let path = index.get_path()?;
        let merge_node = self
            .public_art
            .merge_tree
            .root
            .as_ref()
            .and_then(|root| root.node(&path).ok());

        ArtNodePreview::new(art_node, merge_node)
    }

    pub fn root(&self) -> ArtNodePreview<G> {
        ArtNodePreview::ArtNodeOnly {
            art_node: &self.public_art.tree_root,
        }
    }

    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn co_path(&self, path: &[Direction]) -> Result<Vec<G>, ArtError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.root();
        for direction in path {
            co_path_values.push(
                parent
                    .child(direction.other())
                    .ok_or(ArtError::InvalidInput)?
                    .public_key(),
            );
            parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }
}

impl<'a, G> ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    pub fn new(
        art_node: Option<&'a ArtNode<G>>,
        merge_node: Option<&'a AggregationNode<PublicMergeData<G>>>,
    ) -> Result<Self, ArtError> {
        match (art_node, merge_node) {
            (Some(art_node), Some(merge_node)) => Ok(ArtNodePreview::Full {
                art_node,
                merge_node,
            }),
            (Some(art_node), None) => Ok(ArtNodePreview::ArtNodeOnly { art_node }),
            (None, Some(merge_node)) => Ok(ArtNodePreview::MergeNodeOnly { merge_node }),
            (None, None) => Err(ArtError::InvalidInput),
        }
    }

    pub fn art_node(&self) -> Option<&'a ArtNode<G>> {
        match self {
            ArtNodePreview::ArtNodeOnly { art_node, .. } => Some(art_node),
            ArtNodePreview::MergeNodeOnly { .. } => None,
            ArtNodePreview::Full { art_node, .. } => Some(art_node),
        }
    }

    pub fn merge_node(&self) -> Option<&'a AggregationNode<PublicMergeData<G>>> {
        match self {
            ArtNodePreview::ArtNodeOnly { .. } => None,
            ArtNodePreview::MergeNodeOnly { merge_node, .. } => Some(merge_node),
            ArtNodePreview::Full { merge_node, .. } => Some(merge_node),
        }
    }

    pub fn public_key(&self) -> G {
        match self {
            ArtNodePreview::ArtNodeOnly { art_node } => art_node.public_key(),
            ArtNodePreview::MergeNodeOnly { merge_node } => merge_node.preview_public_key(),
            ArtNodePreview::Full {
                art_node,
                merge_node,
            } => art_node.preview_public_key(&merge_node.data),
        }
    }

    pub(crate) fn child(&self, dir: Direction) -> Option<Self> {
        let art_node: Option<&'a ArtNode<G>> = match self.art_node() {
            Some(node) => node.child(dir),
            None => None,
        };

        let merge_node = match self.merge_node() {
            Some(merge_node) => merge_node.child(dir),
            None => None,
        };

        ArtNodePreview::new(art_node, merge_node).ok()
    }
}
