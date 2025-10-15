use crate::errors::ARTError;
use crate::traits::{ChildContainer, RelatedData};
use crate::types::{AggregationData, AggregationDisplayTree, AggregationNodeIterWithPath, BranchChanges, BranchChangesType, BranchChangesTypeHint, ChangeAggregation, Children, Direction, NodeIndex, ProverAggregationData, ProverArtefacts, VerifierAggregationData};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::{CharSet, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};
use tree_ds::prelude::Node;
use utils::aggregations::{AggregatedNodeData, ProverAggregationTree};

impl<D> ChangeAggregation<D>
where
    D: RelatedData + Clone + Default,
{
    pub fn get_node(&self, path: &[Direction]) -> Result<&Self, ARTError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .children
                .get_child(*direction)
                .ok_or(ARTError::PathNotExists)?;
        }

        Ok(parent)
    }

    pub fn get_mut_node(&mut self, path: &[Direction]) -> Result<&mut Self, ARTError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .children
                .get_mut_child(*direction)
                .ok_or(ARTError::InternalOnly)?;
        }

        Ok(parent)
    }

    /// Return `true` if the specified path exists in the tree, otherwise `false`.
    pub fn contain(&self, path: &[Direction]) -> bool {
        let mut current_node = self;
        for direction in path {
            if let Some(child) = current_node.children.get_child(*direction) {
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
            if let Some(child) = current_node.children.get_child(*dir) {
                intersection.push(*dir);
                current_node = child;
            } else {
                return intersection;
            }
        }

        intersection
    }
}

impl<D> From<D> for ChangeAggregation<D>
where
    D: RelatedData + Clone + Default,
{
    fn from(data: D) -> Self {
        Self {
            children: Children::default(),
            data,
        }
    }
}

impl<G> ChangeAggregation<ProverAggregationData<G>>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::ScalarField: PrimeField,
{
    /// Append `BranchChanges<G>` to the structure by overwriting unnecessary data. utilizes
    /// `change_type_hint` to perform extension correctly
    pub fn extend(
        &mut self,
        change: &BranchChanges<G>,
        prover_artefacts: &ProverArtefacts<G>,
        change_type_hint: BranchChangesTypeHint<G>,
    ) -> Result<(), ARTError> {
        let mut leaf_path = change.node_index.get_path()?;

        if leaf_path.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if let BranchChangesTypeHint::AppendNode { extend: true, .. } = change_type_hint {
            leaf_path.pop();
        }

        self.extend_tree_with(change, prover_artefacts)?;

        let target_leaf = self.get_mut_node(&leaf_path)?;
        target_leaf.data.change_type.push(change_type_hint);

        Ok(())
    }

    fn extend_tree_with(
        &mut self,
        change: &BranchChanges<G>,
        prover_artefacts: &ProverArtefacts<G>,
    ) -> Result<(), ARTError> {
        let leaf_path = change.node_index.get_path()?;

        if change.public_keys.len() != leaf_path.len() + 1
            || prover_artefacts.secrets.len() != leaf_path.len() + 1
            || prover_artefacts.co_path.len() != leaf_path.len()
        {
            return Err(ARTError::InvalidInput);
        }

        // Update root.
        self.data.public_key = *change.public_keys.first().ok_or(ARTError::EmptyART)?;
        self.data.secret_key = *prover_artefacts
            .secrets
            .first()
            .ok_or(ARTError::InvalidInput)?;


        // Update other nodes.
        let mut parent = &mut *self;
        for (i, direction) in leaf_path.iter().enumerate() {
            // compute new child node
            let child_data = ProverAggregationData::<G> {
                public_key: change.public_keys[i + 1],
                co_public_key: Some(
                    prover_artefacts.co_path[prover_artefacts.co_path.len() - i - 1],
                ),
                change_type: vec![],
                secret_key: prover_artefacts.secrets[i + 1],
            };

            // update other_co_path
            if let Some(child) = parent.children.get_mut_child(direction.other()) {
                child.data.co_public_key = Some(change.public_keys[i + 1]);
            }

            // Update parent
            parent = parent
                .children
                .get_mut_child_or_create(*direction)
                .ok_or(ARTError::InvalidInput)?;
            parent.data.aggregate(child_data);
        }

        Ok(())
    }
}

impl<D> Display for ChangeAggregation<D>
where
    D: RelatedData + Clone + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_tree!(
                AggregationDisplayTree::from(self),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::DOUBLE_LINE)
            )
        )
    }
}

impl<D> From<&Box<ChangeAggregation<D>>> for AggregationDisplayTree
where
    D: RelatedData + Clone + Display,
{
    fn from(value: &Box<ChangeAggregation<D>>) -> Self {
        AggregationDisplayTree::from(value.as_ref())
    }
}

impl<D> From<&ChangeAggregation<D>> for AggregationDisplayTree
where
    D: RelatedData + Display + Clone,
{
    fn from(value: &ChangeAggregation<D>) -> Self {
        match &value.children {
            Children::Leaf => AggregationDisplayTree::Leaf {
                public_key: format!("Leaf: {}", value.data,),
            },
            Children::Route { c, direction } => AggregationDisplayTree::Route {
                public_key: format!("Route: {} -> {:?}", value.data, direction),
                child: Box::new(c.into()),
            },
            Children::Node { l, r } => AggregationDisplayTree::Node {
                public_key: format!("Node {}", value.data),
                left: Box::new(l.into()),
                right: Box::new(r.into()),
            },
        }
    }
}

impl<G> From<&ProverAggregationData<G>> for AggregatedNodeData<G>
where
    G: AffineRepr,
{
    fn from(value: &ProverAggregationData<G>) -> Self {
        Self {
            public_key: value.public_key,
            co_public_key: value.co_public_key,
            secret_key: value.secret_key,
            marker: false,
        }
    }
}

impl<D1, D2> TryFrom<&ChangeAggregation<D1>> for ChangeAggregation<D2>
where
    D1: RelatedData + Clone + Default,
    D2: RelatedData + From<D1> + Clone + Default,
{
    type Error = ARTError;

    fn try_from(prover_aggregation: &ChangeAggregation<D1>) -> Result<Self, Self::Error> {
        let mut iter = AggregationNodeIterWithPath::new(prover_aggregation);
        let (node, _) = iter.next().ok_or(ARTError::EmptyART)?;

        let verifier_data = D2::from(node.data.clone());
        let mut aggregation = ChangeAggregation::from(verifier_data);

        for (node, path) in iter {
            let mut node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let verifier_data = D2::from(node.data.clone());
                let next_node = ChangeAggregation::from(verifier_data);

                if let Ok(child) = aggregation.get_mut_node(&*node_path) {
                    child.children.set_child(last_dir, next_node);
                }
            }
        }

        Ok(aggregation)
    }
}

impl<G> TryFrom<&ChangeAggregation<ProverAggregationData<G>>> for ProverAggregationTree<G>
where
    G: AffineRepr,
{
    type Error = ARTError;

    fn try_from(value: &ChangeAggregation<ProverAggregationData<G>>) -> Result<Self, Self::Error> {
        let mut resulting_tree: Self = Self::new(None);

        let mut node_iter = AggregationNodeIterWithPath::new(&value);

        let (root, _) = node_iter.next().ok_or(ARTError::EmptyART)?;
        resulting_tree
            .add_node(
                Node::new(1, Some(AggregatedNodeData::from(&root.data))),
                None,
            )
            .unwrap();

        for (agg_node, path) in node_iter {
            let node_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            let node_id = NodeIndex::get_index_from_path(&node_path)?;
            let parent_id = node_id / 2;
            resulting_tree
                .add_node(
                    Node::new(node_id, Some(AggregatedNodeData::from(&agg_node.data))),
                    Some(&parent_id),
                )
                .map_err(|_| ARTError::TreeDS)?;
        }

        Ok(resulting_tree)
    }
}

/// NodeIter iterates over all the nodes, performing a depth-first traversal
impl<'a, D> AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub fn new(root: &'a ChangeAggregation<D>) -> Self {
        AggregationNodeIterWithPath {
            current_node: Some(root),
            path: vec![],
        }
    }
}

impl<'a, D> Iterator for AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone + Default,
{
    type Item = (
        &'a ChangeAggregation<D>,
        Vec<(&'a ChangeAggregation<D>, Direction)>,
    );

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_node) = self.current_node {
            let return_item = (current_node, self.path.clone());

            match &current_node.children {
                Children::Node { l, .. } => {
                    // Try to go further down, to the left. The right case will be handled by the leaf case.
                    self.path.push((current_node, Direction::Left));
                    self.current_node = Some(l.as_ref());
                }
                Children::Route { c, direction } => {
                    // Try to go further down. Pass through.
                    self.path.push((current_node, *direction));
                    self.current_node = Some(c.as_ref());
                }
                Children::Leaf => {
                    loop {
                        if let Some((parent, last_direction)) = self.path.pop() {
                            if let Children::Node { .. } = &parent.children {
                                // Try to go right, or else go up
                                if last_direction == Direction::Right {
                                    // Go up.
                                    self.current_node = Some(parent);
                                } else if last_direction == Direction::Left {
                                    // go on the right.
                                    self.path.push((parent, Direction::Right));
                                    self.current_node = parent
                                        .children
                                        .get_child(Direction::Right)
                                        .map(|item| item);
                                    break;
                                }
                            } else if let Children::Route { .. } = &parent.children {
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

impl<G> From<ProverAggregationData<G>> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn from(prover_data: ProverAggregationData<G>) -> Self {
        Self {
            public_key: prover_data.public_key,
            co_public_key: prover_data.co_public_key,
            change_type: prover_data.change_type,
        }
    }
}

impl<G> From<ProverAggregationData<G>> for AggregationData<G>
where
    G: AffineRepr,
{
    fn from(prover_data: ProverAggregationData<G>) -> Self {
        Self {
            public_key: prover_data.public_key,
            change_type: prover_data.change_type,
        }
    }
}

impl<G> From<VerifierAggregationData<G>> for AggregationData<G>
where
    G: AffineRepr,
{
    fn from(verifier_data: VerifierAggregationData<G>) -> Self {
        Self {
            public_key: verifier_data.public_key,
            change_type: verifier_data.change_type,
        }
    }
}

impl<G> From<AggregationData<G>> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn from(aggregation_data: AggregationData<G>) -> Self {
        Self {
            public_key: aggregation_data.public_key,
            co_public_key: None,
            change_type: aggregation_data.change_type,
        }
    }
}

impl<G> Display for ProverAggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        let sk_marker = self
            .secret_key
            .to_string()
            .chars()
            .take(8)
            .collect::<String>()
            + "...";

        write!(
            f,
            "pk: {}, co_pk: {}, sk: {}, type: {:?}",
            pk_marker, co_pk_marker, sk_marker,
            self.change_type
                .iter()
                .map(|change_type| BranchChangesType::from(change_type))
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> Display for VerifierAggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        write!(
            f,
            "pk: {}, co_pk: {}, type: {:?}",
            pk_marker, co_pk_marker,
            self.change_type
                .iter()
                .map(|change_type| BranchChangesType::from(change_type))
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> Display for AggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        write!(
            f,
            "pk: {}, type: {:?}",
            pk_marker,
            self.change_type
            .iter()
            .map(|change_type| BranchChangesType::from(change_type))
            .collect::<Vec<_>>(),
        )
    }
}
