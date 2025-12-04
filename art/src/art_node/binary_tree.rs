use crate::art::ProverArtefacts;
use crate::art_node::{ArtNode, ArtNodePreview};
use crate::changes::aggregations::{ProverAggregationData, VerifierAggregationData};
use crate::changes::branch_change::{BranchChange, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use tree_ds::prelude::Node;
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};
use zrt_zk::art::{ProverNodeData, VerifierNodeData};

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

/// Node of the aggregation tree. nodes contain data of some generic type `D`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryTreeNode<D> {
    pub(crate) l: Option<Box<Self>>,
    pub(crate) r: Option<Box<Self>>,
    pub data: D,
}

impl<D> BinaryTreeNode<D> {
    pub fn new_leaf(data: D) -> Self {
        Self {
            l: None,
            r: None,
            data,
        }
    }

    pub fn new_internal(data: D, l: Option<Box<Self>>, r: Option<Box<Self>>) -> Self {
        Self { l, r, data }
    }

    pub fn data(&self) -> &D {
        &self.data
    }

    pub fn node_at(&self, path: &[Direction]) -> Result<&Self, ArtError> {
        let mut parent = self;
        for direction in path {
            parent = parent.child(*direction).ok_or(ArtError::PathNotExists)?;
        }

        Ok(parent)
    }

    pub fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    pub fn mut_node_at(&mut self, path: &[Direction]) -> Result<&mut Self, ArtError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .mut_child(*direction)
                .as_mut()
                .ok_or(ArtError::InternalNodeOnly)?;
        }

        Ok(parent)
    }

    /// Return `true` if the specified path exists in the tree, otherwise `false`.
    pub fn contains(&self, path: &[Direction]) -> bool {
        let mut current_node = self;
        for direction in path {
            if let Some(child) = current_node.child(*direction) {
                current_node = child;
            } else {
                return false;
            }
        }

        true
    }

    /// Returns a common path between aggregation `self`, and the given `path`.
    pub fn get_intersection(&self, path: &[Direction]) -> Vec<Direction> {
        let mut intersection = Vec::new();
        let mut current_node = self;
        for dir in path {
            if let Some(child) = current_node.child(*dir) {
                intersection.push(*dir);
                current_node = child;
            } else {
                return intersection;
            }
        }

        intersection
    }

    pub fn get_mut_node_with_path(&mut self, path: &[Direction]) -> Result<&mut Self, ArtError> {
        let mut current_node = self;
        for dir in path {
            current_node = current_node
                .mut_child(*dir)
                .as_mut()
                .ok_or(ArtError::PathNotExists)?;
        }

        Ok(current_node)
    }

    /// Returns a mutable reference on a child at the given direction `dir`. If it is None, then
    /// Create a new one, and return a mutable reference on a new child.
    fn get_or_insert_default(&mut self, dir: Direction) -> &mut Self
    where
        Self: Default,
    {
        match dir {
            Direction::Left => self.l.get_or_insert_default(),
            Direction::Right => self.r.get_or_insert_default(),
        }
    }

    fn set_child(&mut self, dir: Direction, node: Self) -> &mut Self
    where
        Self: Default,
    {
        let child = match dir {
            Direction::Left => self.l.get_or_insert_default(),
            Direction::Right => self.r.get_or_insert_default(),
        };

        *child = Box::new(node);
        child.as_mut()
    }

    pub fn node_iter_with_path(&self) -> NodeIterWithPath<&Self> {
        NodeIterWithPath::new(self)
    }

    pub fn leaf_iter_with_path(&self) -> LeafIterWithPath<&Self> {
        LeafIterWithPath::new(self)
    }

    pub fn node_iter(&self) -> NodeIter<&Self> {
        NodeIter::new(self)
    }

    pub fn leaf_iter(&self) -> LeafIter<&Self> {
        LeafIter::new(self)
    }
}

impl<G> BinaryTreeNode<ProverAggregationData<G>>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::ScalarField: PrimeField,
{
    /// Append `BranchChange<G>` to the structure by overwriting unnecessary data. utilizes
    /// `change_type_hint` to perform extension correctly
    pub fn extend(
        &mut self,
        change: &BranchChange<G>,
        prover_artefacts: &ProverArtefacts<G>,
        change_type_hint: BranchChangeTypeHint<G>,
    ) -> Result<(), ArtError> {
        let mut leaf_path = change.node_index.get_path()?;

        if leaf_path.is_empty() {
            return Err(ArtError::NoChanges);
        }

        if matches!(
            change_type_hint,
            BranchChangeTypeHint::AddMember {
                ext_pk: Some(_),
                ..
            }
        ) {
            leaf_path.pop();
        }

        self.extend_tree_with(change, prover_artefacts)?;

        let target_leaf = self.mut_node_at(&leaf_path)?;
        target_leaf.data.change_type.push(change_type_hint);

        Ok(())
    }

    fn extend_tree_with(
        &mut self,
        change: &BranchChange<G>,
        prover_artefacts: &ProverArtefacts<G>,
    ) -> Result<(), ArtError> {
        let leaf_path = change.node_index.get_path()?;

        if change.public_keys.len() != leaf_path.len() + 1
            || prover_artefacts.secrets.len() != leaf_path.len() + 1
            || prover_artefacts.co_path.len() != leaf_path.len()
        {
            return Err(ArtError::InvalidInput);
        }

        // Update root.
        self.data.public_key = *prover_artefacts.path.last().ok_or(ArtError::EmptyArt)?;
        self.data.secret_key = *prover_artefacts
            .secrets
            .last()
            .ok_or(ArtError::InvalidInput)?;

        // Update other nodes.
        let mut parent = &mut *self;
        for (i, dir) in leaf_path.iter().rev().enumerate().rev() {
            // compute new child node
            let child_data = ProverAggregationData::<G> {
                // public_key: change.public_keys[i + 1],
                public_key: prover_artefacts.path[i],
                co_public_key: Some(prover_artefacts.co_path[i]),
                change_type: vec![],
                secret_key: prover_artefacts.secrets[i],
            };

            // update other_co_path
            if let Some(child) = parent.mut_child(dir.other()) {
                child.data.co_public_key = Some(change.public_keys[i + 1]);
            }

            // Update co_node
            if let Some(co_node) = parent.mut_child(dir.other()) {
                co_node.data.co_public_key = Some(child_data.public_key);
            }

            // Update parent
            parent = parent.get_or_insert_default(*dir);
            parent.data.aggregate_with(child_data);
        }

        Ok(())
    }
}

// impl<D> TreeNode<AggregationNode<D>> for AggregationNode<D>
impl<D> BinaryTreeNode<D> {
    /// Return a reference on a child on the given direction. Return None, if there is no
    /// child there.
    pub(crate) fn child(&self, dir: Direction) -> Option<&Self> {
        match dir {
            Direction::Right => self.r.as_ref().map(|node| node.as_ref()),
            Direction::Left => self.l.as_ref().map(|node| node.as_ref()),
        }
    }

    /// Return a mutable reference on a child on the given direction. Return None,
    /// if there is no child there.
    pub(crate) fn mut_child(&mut self, dir: Direction) -> &mut Option<Box<Self>> {
        match dir {
            Direction::Right => &mut self.r,
            Direction::Left => &mut self.l,
        }
    }
}

impl<D> From<D> for BinaryTreeNode<D>
where
// D: RelatedData + Clone + Default,
{
    fn from(data: D) -> Self {
        Self {
            l: None,
            r: None,
            data,
        }
    }
}

impl<D1, D2> TryFrom<&BinaryTreeNode<D1>> for BinaryTreeNode<D2>
where
    D1: Clone + Default,
    D2: From<D1> + Clone + Default,
{
    type Error = ArtError;

    fn try_from(prover_aggregation: &BinaryTreeNode<D1>) -> Result<Self, Self::Error> {
        let mut iter = NodeIterWithPath::new(prover_aggregation);
        let (node, _) = iter.next().ok_or(ArtError::EmptyArt)?;

        let verifier_data = D2::from(node.data.clone());
        let mut aggregation = BinaryTreeNode::from(verifier_data);

        for (node, path) in iter {
            let mut node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let verifier_data = D2::from(node.data.clone());
                let next_node = BinaryTreeNode::from(verifier_data);

                if let Ok(child) = aggregation.mut_node_at(&node_path) {
                    child.set_child(last_dir, next_node);
                }
            }
        }

        Ok(aggregation)
    }
}

impl<G> TryFrom<&ArtNode<G>> for BinaryTreeNode<bool>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(prover_aggregation: &ArtNode<G>) -> Result<Self, Self::Error> {
        let mut iter = LeafIterWithPath::new(prover_aggregation);
        let (_, _) = iter.next().ok_or(ArtError::EmptyArt)?;

        let mut aggregation = BinaryTreeNode::from(false);

        for (_, path) in iter {
            let mut node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let next_node = BinaryTreeNode::from(false);

                if let Ok(child) = aggregation.mut_node_at(&node_path) {
                    child.set_child(last_dir, next_node);
                }
            }
        }

        Ok(aggregation)
    }
}

impl<G> TryFrom<&BinaryTreeNode<ProverAggregationData<G>>> for ProverAggregationTree<G>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(value: &BinaryTreeNode<ProverAggregationData<G>>) -> Result<Self, Self::Error> {
        let mut resulting_tree: Self = Self::new(None);

        let mut node_iter = NodeIterWithPath::new(value);

        let (root, _) = node_iter.next().ok_or(ArtError::EmptyArt)?;
        resulting_tree
            .add_node(Node::new(1, Some(ProverNodeData::from(&root.data))), None)
            .map_err(|_| ArtError::TreeDs)?;

        for (agg_node, path) in node_iter {
            let node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            let node_id = NodeIndex::get_index_from_path(&node_path)?;
            let parent_id = node_id / 2;
            resulting_tree
                .add_node(
                    Node::new(node_id, Some(ProverNodeData::from(&agg_node.data))),
                    Some(&parent_id),
                )
                .map_err(|_| ArtError::TreeDs)?;
        }

        Ok(resulting_tree)
    }
}

impl<G> TryFrom<&BinaryTreeNode<VerifierAggregationData<G>>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(value: &BinaryTreeNode<VerifierAggregationData<G>>) -> Result<Self, Self::Error> {
        let mut resulting_tree: Self = Self::new(None);

        let mut node_iter = NodeIterWithPath::new(value);

        let (root, _) = node_iter.next().ok_or(ArtError::EmptyArt)?;
        resulting_tree
            .add_node(Node::new(1, Some(VerifierNodeData::from(&root.data))), None)
            .map_err(|_| ArtError::TreeDs)?;

        for (agg_node, path) in node_iter {
            let node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            let node_id = NodeIndex::get_index_from_path(&node_path)?;
            let parent_id = node_id / 2;
            resulting_tree
                .add_node(
                    Node::new(node_id, Some(VerifierNodeData::from(&agg_node.data))),
                    Some(&parent_id),
                )
                .map_err(|_| ArtError::TreeDs)?;
        }

        Ok(resulting_tree)
    }
}

/// Iterator for a binary tree.
///
/// `NodeIterWithPath` can be used for traversal of all the nodes in the
/// binary tree. Besides the target node, this iterator is meant to return pairs of
/// node and path direction `(N, Direction)` on path from the root to the current node.
#[derive(Debug, Clone)]
pub struct NodeIterWithPath<N> {
    pub(crate) current_node: Option<N>,
    pub(crate) path: Vec<(N, Direction)>,
}

impl<N> NodeIterWithPath<N> {
    pub fn new(root: N) -> Self {
        NodeIterWithPath {
            current_node: Some(root),
            path: vec![],
        }
    }
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, D> From<&'a BinaryTree<D>> for NodeIterWithPath<&'a BinaryTreeNode<D>> {
    fn from(value: &'a BinaryTree<D>) -> Self {
        match &value.root {
            None => NodeIterWithPath {
                current_node: None,
                path: vec![],
            },
            Some(root) => Self::new(root),
        }
    }
}

impl<'a, D> Iterator for NodeIterWithPath<&'a BinaryTreeNode<D>> {
    type Item = (
        &'a BinaryTreeNode<D>,
        Vec<(&'a BinaryTreeNode<D>, Direction)>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_node) = self.current_node {
            let return_item = (current_node, self.path.clone());

            match (&current_node.l, &current_node.r) {
                (Some(l), Some(_)) => {
                    // Try to go further down, to the left. The right case will be handled by the leaf case.
                    self.path.push((current_node, Direction::Left));
                    self.current_node = Some(l.as_ref());
                }
                (Some(l), None) => {
                    // Try to go further down. Pass through.
                    self.path.push((current_node, Direction::Left));
                    self.current_node = Some(l.as_ref());
                }
                (None, Some(r)) => {
                    // Try to go further down. Pass through.
                    self.path.push((current_node, Direction::Right));
                    self.current_node = Some(r.as_ref());
                }
                (None, None) => {
                    loop {
                        if let Some((parent, last_direction)) = self.path.pop() {
                            if let (Some(_), Some(_)) = (&parent.l, &parent.r) {
                                // Try to go right, or else go up
                                if last_direction == Direction::Right {
                                    // Go up.
                                    self.current_node = Some(parent);
                                } else if last_direction == Direction::Left {
                                    // go on the right.
                                    self.path.push((parent, Direction::Right));
                                    self.current_node = parent.child(Direction::Right);
                                    break;
                                }
                            } else if let (Some(_), None) | (None, Some(_)) = (&parent.l, &parent.r)
                            {
                                // Go up
                                self.current_node = Some(parent);
                            } // parent node can't be a leaf node
                        } else {
                            self.current_node = None;
                            return Some(return_item);
                        }
                    }
                }
            }

            return Some(return_item);
        }

        None
    }
}

impl<'a, G> Iterator for NodeIterWithPath<ArtNodePreview<'a, G>>
where
    G: AffineRepr,
{
    type Item = (
        ArtNodePreview<'a, G>,
        Vec<(ArtNodePreview<'a, G>, Direction)>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_node) = self.current_node {
            let return_item = (current_node, self.path.clone());

            match (
                current_node.child(Direction::Left),
                current_node.child(Direction::Right),
            ) {
                // (&current_node.l, &current_node.r)
                (Some(l), Some(_)) => {
                    // Try to go further down, to the left. The right case will be handled by the leaf case.
                    self.path.push((current_node, Direction::Left));
                    self.current_node = Some(l);
                }
                (Some(l), None) => {
                    // Try to go further down. Pass through.
                    self.path.push((current_node, Direction::Left));
                    self.current_node = Some(l);
                }
                (None, Some(r)) => {
                    // Try to go further down. Pass through.
                    self.path.push((current_node, Direction::Right));
                    self.current_node = Some(r);
                }
                (None, None) => {
                    loop {
                        if let Some((parent, last_direction)) = self.path.pop() {
                            if let (Some(_), Some(_)) = (
                                parent.child(Direction::Left),
                                parent.child(Direction::Right),
                            ) {
                                // Try to go right, or else go up
                                if last_direction == Direction::Right {
                                    // Go up.
                                    self.current_node = Some(parent);
                                } else if last_direction == Direction::Left {
                                    // go on the right.
                                    self.path.push((parent, Direction::Right));
                                    self.current_node = parent.child(Direction::Right);
                                    break;
                                }
                            } else if let (Some(_), None) | (None, Some(_)) = (
                                parent.child(Direction::Left),
                                parent.child(Direction::Right),
                            ) {
                                // Go up
                                self.current_node = Some(parent);
                            } // parent node can't be a leaf node
                        } else {
                            self.current_node = None;
                            return Some(return_item);
                        }
                    }
                }
            }

            return Some(return_item);
        }

        None
    }
}

/// `LeafIterWithPath` iterates over all the leaves in a tree from left most to right most,
/// performing a depth-first traversal.
///
/// Along with the leaf, this iterator returns pairs `(Node, Direction)` on path from
/// root to the node, as `NodeIterWithPath` do.
pub struct LeafIterWithPath<N> {
    inner_iter: NodeIterWithPath<N>,
}

impl<N> LeafIterWithPath<N> {
    pub fn new(root: N) -> Self {
        Self {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, D> Iterator for LeafIterWithPath<&'a BinaryTreeNode<D>> {
    type Item = (
        &'a BinaryTreeNode<D>,
        Vec<(&'a BinaryTreeNode<D>, Direction)>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        for (item, path) in &mut self.inner_iter {
            if item.is_leaf() {
                return Some((item, path));
            }
        }

        None
    }
}

impl<'a, G: AffineRepr> Iterator for LeafIterWithPath<ArtNodePreview<'a, G>> {
    type Item = (
        ArtNodePreview<'a, G>,
        Vec<(ArtNodePreview<'a, G>, Direction)>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        for (item, path) in &mut self.inner_iter {
            if item.is_leaf() {
                return Some((item, path));
            }
        }

        None
    }
}

/// `BinaryNodeIter` iterates over all the nodes, performing a depth-first traversal.
pub struct NodeIter<N> {
    pub inner_iter: NodeIterWithPath<N>,
}

impl<N> NodeIter<N> {
    pub fn new(root: N) -> Self {
        Self {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, D> Iterator for NodeIter<&'a BinaryTreeNode<D>> {
    type Item = &'a BinaryTreeNode<D>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter.next().map(|item| item.0)
    }
}

impl<'a, G: AffineRepr> Iterator for NodeIter<ArtNodePreview<'a, G>> {
    type Item = ArtNodePreview<'a, G>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_iter.next().map(|item| item.0)
    }
}

/// `LeafIter` iterates over leaves from left most to right most, performing a depth-first traversal
pub struct LeafIter<N> {
    pub inner_iter: NodeIterWithPath<N>,
}

impl<N> LeafIter<N> {
    pub fn new(root: N) -> Self {
        LeafIter {
            inner_iter: NodeIterWithPath::new(root),
        }
    }
}

impl<'a, D> Iterator for LeafIter<&'a BinaryTreeNode<D>> {
    type Item = &'a BinaryTreeNode<D>;

    fn next(&mut self) -> Option<Self::Item> {
        (&mut self.inner_iter)
            .map(|(item, _)| item)
            .find(|&item| item.is_leaf())
    }
}

impl<'a, G: AffineRepr> Iterator for LeafIter<ArtNodePreview<'a, G>> {
    type Item = ArtNodePreview<'a, G>;

    fn next(&mut self) -> Option<Self::Item> {
        (&mut self.inner_iter)
            .map(|(item, _)| item)
            .find(|&item| item.is_leaf())
    }
}

impl<'a, D> IntoIterator for &'a BinaryTreeNode<D> {
    type Item = &'a BinaryTreeNode<D>;
    type IntoIter = LeafIter<&'a BinaryTreeNode<D>>;

    fn into_iter(self) -> Self::IntoIter {
        self.leaf_iter()
    }
}

impl<'a, G: AffineRepr> IntoIterator for ArtNodePreview<'a, G> {
    type Item = ArtNodePreview<'a, G>;
    type IntoIter = LeafIter<ArtNodePreview<'a, G>>;

    fn into_iter(self) -> Self::IntoIter {
        self.leaf_iter()
    }
}
