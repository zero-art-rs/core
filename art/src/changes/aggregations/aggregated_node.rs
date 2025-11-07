use crate::art::ProverArtefacts;
use crate::art::art_node::{ArtNode, NodeIterWithPath};
use crate::changes::aggregations::{
    AggregationData, AggregationTree, ProverAggregationData, RelatedData, VerifierAggregationData,
};
use crate::changes::branch_change::{BranchChange, BranchChangesTypeHint};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use tree_ds::prelude::Node;
use zrt_zk::{
    aggregated_art::{ProverAggregationTree, VerifierAggregationTree},
    art::{ProverNodeData, VerifierNodeData},
};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregationNode<D>
// where
//     D: RelatedData + Clone,
{
    pub l: Option<Box<Self>>,
    pub r: Option<Box<Self>>,
    pub data: D,
}

impl<D> AggregationNode<D> {
    pub fn get_node(&self, path: &[Direction]) -> Result<&Self, ArtError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .get_child(*direction)
                .ok_or(ArtError::PathNotExists)?;
        }

        Ok(parent)
    }

    pub fn get_mut_node(&mut self, path: &[Direction]) -> Result<&mut Self, ArtError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .get_mut_child(*direction)
                .ok_or(ArtError::InternalNodeOnly)?;
        }

        Ok(parent)
    }

    /// Return `true` if the specified path exists in the tree, otherwise `false`.
    pub fn contains(&self, path: &[Direction]) -> bool {
        let mut current_node = self;
        for direction in path {
            if let Some(child) = current_node.get_child(*direction) {
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
            if let Some(child) = current_node.get_child(*dir) {
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
            current_node = current_node.get_mut_child(*dir).ok_or(ArtError::PathNotExists)?;
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
}

impl<G> AggregationNode<ProverAggregationData<G>>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::ScalarField: PrimeField,
{
    /// Append `BranchChange<G>` to the structure by overwriting unnecessary data. utilizes
    /// `change_type_hint` to perform extension correctly
    pub fn extend<R: Rng + ?Sized>(
        &mut self,
        rng: &mut R,
        change: &BranchChange<G>,
        prover_artefacts: &ProverArtefacts<G>,
        change_type_hint: BranchChangesTypeHint<G>,
    ) -> Result<(), ArtError> {
        let mut leaf_path = change.node_index.get_path()?;

        if leaf_path.is_empty() {
            return Err(ArtError::EmptyArt);
        }

        if let BranchChangesTypeHint::AddMember {
            ext_pk: Some(_), ..
        } = change_type_hint
        {
            leaf_path.pop();
        }

        self.extend_tree_with(rng, change, prover_artefacts)?;

        let target_leaf = self.get_mut_node(&leaf_path)?;
        target_leaf.data.change_type.push(change_type_hint);

        Ok(())
    }

    fn extend_tree_with<R: Rng + ?Sized>(
        &mut self,
        rng: &mut R,
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
                blinding_factor: G::ScalarField::rand(rng),
            };

            // update other_co_path
            if let Some(child) = parent.get_mut_child(dir.other()) {
                child.data.co_public_key = Some(change.public_keys[i + 1]);
            }

            // Update co_node
            if let Some(co_node) = parent.get_mut_child(dir.other()) {
                co_node.data.co_public_key = Some(child_data.public_key);
            }

            // Update parent
            parent = parent.get_or_insert_default(*dir);
            parent.data.aggregate(child_data);
        }

        Ok(())
    }
}

impl<G> AggregationNode<AggregationData<G>>
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
        change_type_hint: BranchChangesTypeHint<G>,
    ) -> Result<(), ArtError> {
        let mut leaf_path = change.node_index.get_path()?;

        if leaf_path.is_empty() {
            return Err(ArtError::EmptyArt);
        }

        if let BranchChangesTypeHint::AddMember {
            ext_pk: Some(_), ..
        } = change_type_hint
        {
            leaf_path.pop();
        }

        self.extend_tree_with(change, prover_artefacts)?;

        let target_leaf = self.get_mut_node(&leaf_path)?;
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

        // Update other nodes.
        let mut parent = &mut *self;
        for (i, dir) in leaf_path.iter().rev().enumerate().rev() {
            // compute new child node
            let child_data = AggregationData::<G> {
                // public_key: change.public_keys[i + 1],
                public_key: prover_artefacts.path[i],
                change_type: vec![],
            };

            // Update parent
            parent = parent.get_or_insert_default(*dir);
            parent.data.aggregate(child_data);
        }

        Ok(())
    }
}

// impl<D> TreeNode<AggregationNode<D>> for AggregationNode<D>
impl<D> AggregationNode<D>
// where
//     D: RelatedData + Clone + Default,
{
    /// Return a reference on a child on the given direction. Return None, if there is no
    /// child there.
    pub(crate) fn get_child(&self, dir: Direction) -> Option<&Self> {
        let child = match dir {
            Direction::Right => self.r.as_ref(),
            Direction::Left => self.l.as_ref(),
        };

        child.map(|r| r.as_ref())
    }

    /// Return a mutable reference on a child on the given direction. Return None,
    /// if there is no child there.
    pub(crate) fn get_mut_child(&mut self, dir: Direction) -> Option<&mut Self> {
        let child = match dir {
            Direction::Right => self.r.as_mut(),
            Direction::Left => self.l.as_mut(),
        };

        child.map(|r| r.as_mut())
    }
}

impl<D> From<D> for AggregationNode<D>
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

impl<D1, D2> TryFrom<&AggregationNode<D1>> for AggregationNode<D2>
where
    D1: RelatedData + Clone + Default,
    D2: RelatedData + From<D1> + Clone + Default,
{
    type Error = ArtError;

    fn try_from(prover_aggregation: &AggregationNode<D1>) -> Result<Self, Self::Error> {
        let mut iter = AggregationNodeIterWithPath::new(prover_aggregation);
        let (node, _) = iter.next().ok_or(ArtError::EmptyArt)?;

        let verifier_data = D2::from(node.data.clone());
        let mut aggregation = AggregationNode::from(verifier_data);

        for (node, path) in iter {
            let mut node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let verifier_data = D2::from(node.data.clone());
                let next_node = AggregationNode::from(verifier_data);

                if let Ok(child) = aggregation.get_mut_node(&node_path) {
                    child.set_child(last_dir, next_node);
                }
            }
        }

        Ok(aggregation)
    }
}

impl<G> TryFrom<&ArtNode<G>> for AggregationNode<bool>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(prover_aggregation: &ArtNode<G>) -> Result<Self, Self::Error> {
        let mut iter = NodeIterWithPath::new(prover_aggregation);
        let (_, _) = iter.next().ok_or(ArtError::EmptyArt)?;

        let mut aggregation = AggregationNode::from(false);

        for (_, path) in iter {
            let mut node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let next_node = AggregationNode::from(false);

                if let Ok(child) = aggregation.get_mut_node(&node_path) {
                    child.set_child(last_dir, next_node);
                }
            }
        }

        Ok(aggregation)
    }
}

impl<G> TryFrom<&AggregationNode<ProverAggregationData<G>>> for ProverAggregationTree<G>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(value: &AggregationNode<ProverAggregationData<G>>) -> Result<Self, Self::Error> {
        let mut resulting_tree: Self = Self::new(None);

        let mut node_iter = AggregationNodeIterWithPath::new(value);

        let (root, _) = node_iter.next().ok_or(ArtError::EmptyArt)?;
        resulting_tree
            .add_node(Node::new(1, Some(ProverNodeData::from(&root.data))), None)
            .map_err(|_| Self::Error::TreeDs)?;

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

impl<G> TryFrom<&AggregationNode<VerifierAggregationData<G>>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(value: &AggregationNode<VerifierAggregationData<G>>) -> Result<Self, Self::Error> {
        let mut resulting_tree: Self = Self::new(None);

        let mut node_iter = AggregationNodeIterWithPath::new(value);

        let (root, _) = node_iter.next().ok_or(ArtError::EmptyArt)?;
        resulting_tree
            .add_node(Node::new(1, Some(VerifierNodeData::from(&root.data))), None)
            .map_err(|_| Self::Error::TreeDs)?;

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

#[derive(Debug, Clone)]
pub struct AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub current_node: Option<&'a AggregationNode<D>>,
    pub path: Vec<(&'a AggregationNode<D>, Direction)>,
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, D> AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub fn new(root: &'a AggregationNode<D>) -> Self {
        AggregationNodeIterWithPath {
            current_node: Some(root),
            path: vec![],
        }
    }
}

impl<'a, D> From<&'a AggregationTree<D>> for AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    fn from(value: &'a AggregationTree<D>) -> Self {
        match &value.root {
            None => AggregationNodeIterWithPath {
                current_node: None,
                path: vec![],
            },
            Some(root) => Self::new(root),
        }
    }
}

impl<'a, D> Iterator for AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone + Default,
{
    type Item = (
        &'a AggregationNode<D>,
        Vec<(&'a AggregationNode<D>, Direction)>,
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
                                    self.current_node = parent.get_child(Direction::Right);
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
