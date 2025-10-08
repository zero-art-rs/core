use crate::errors::ARTError;
use crate::traits::{ChildContainer, HasChangeTypeHint, HasPublicKey, RelatedData};
use crate::types::{
    AggregationChangeType, AggregationDisplayTree, AggregationNodeIterWithPath, BranchChanges,
    BranchChangesIter, BranchChangesType, BranchChangesTypeHint, ChangeAggregation, Children,
    Direction, NodeIndex, ProverAggregationData, ProverArtefacts, VerifierAggregationData,
};
use ark_ec::AffineRepr;
use ark_ec::hashing::curve_maps::parity;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use display_tree::{CharSet, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};
use tracing::debug;

impl<D> ChangeAggregation<D>
where
    D: RelatedData + Clone + Default,
{
    pub fn get_node(&self, path: &Vec<Direction>) -> Result<&Self, ARTError> {
        let mut parent = self;
        for direction in path {
            parent = parent
                .children
                .get_child(*direction)
                .ok_or(ARTError::InvalidInput)?;
        }

        Ok(parent)
    }

    pub fn get_mut_node(&mut self, path: &[Direction]) -> Result<&mut Self, ARTError> {
        let mut parent = &mut *self;
        for direction in path {
            parent = parent
                .children
                .get_mut_child(*direction)
                .ok_or(ARTError::InvalidInput)?;
        }

        Ok(parent)
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
        change_type_hint: BranchChangesTypeHint,
    ) -> Result<(), ARTError> {
        let mut leaf_path = change.node_index.get_path()?;

        if leaf_path.is_empty() {
            return Err(ARTError::EmptyART);
        }

        match change.change_type {
            BranchChangesType::UpdateKey => {}
            BranchChangesType::MakeBlank => {}
            BranchChangesType::AppendNode => {
                if let BranchChangesTypeHint::AppendNode { extend } = change_type_hint {
                    if extend {
                        leaf_path.pop();
                    }
                }
            }
        }

        let stashed_leaf = self
            .get_node(&leaf_path)
            .ok()
            .map(|node| node.data.public_key);

        self.extend_tree_with(change, prover_artefacts)?;

        let target_leaf = self.get_mut_node(&leaf_path)?;
        target_leaf.data.change_type.push(change_type_hint);

        if let BranchChangesTypeHint::AppendNode { extend } = change_type_hint
            && extend
            && let Some(stashed_leaf) = stashed_leaf
        {
            let other_leaf = target_leaf
                .children
                .get_mut_child_or_create(Direction::Left)
                .ok_or(ARTError::ARTLogicError)?;
            other_leaf.data.public_key = stashed_leaf;
            other_leaf
                .data
                .change_type
                .push(BranchChangesTypeHint::AppendNodeFix);
        }

        Ok(())
    }

    fn extend_tree_with(
        &mut self,
        change: &BranchChanges<G>,
        prover_artefacts: &ProverArtefacts<G>,
    ) -> Result<(), ARTError> {
        let leaf_path = change.node_index.get_path()?;

        // Update root.
        self.data.public_key = *change.public_keys.first().ok_or(ARTError::EmptyART)?;
        self.data.secret_key = *prover_artefacts
            .secrets
            .first()
            .ok_or(ARTError::InvalidInput)?;
        // if leaf_path.is_empty() {
        //     self.data.change_type.push(change.change_type);
        // }

        // Update other nodes.
        let mut parent = &mut *self;
        for (i, direction) in leaf_path.iter().enumerate() {
            // compute new child node
            let child_data = ProverAggregationData::<G> {
                public_key: *change
                    .public_keys
                    .get(i + 1)
                    .ok_or(ARTError::InvalidInput)?,
                co_public_key: Some(
                    *prover_artefacts
                        .co_path
                        .get(i)
                        .ok_or(ARTError::InvalidInput)?,
                ),
                change_type: vec![],
                secret_key: *prover_artefacts
                    .secrets
                    .get(i + 1)
                    .ok_or(ARTError::InvalidInput)?,
                latest: parent.children.get_child(direction.other()).is_none(),
            };

            // Update parent
            parent = parent
                .children
                .get_mut_child_or_create(*direction)
                .ok_or(ARTError::InvalidInput)?;
            parent.data.extend(child_data);
        }

        // parent.data.change_type.push(change.change_type);

        Ok(())
    }
}

impl<G> ChangeAggregation<VerifierAggregationData<G>>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::ScalarField: PrimeField,
{
    fn get_mut_child_at(&mut self, path: &[Direction]) -> Option<&mut Self> {
        let mut parent = self;
        for dir in path {
            if let Some(child) = parent.children.get_mut_child(*dir) {
                parent = child;
            } else {
                return None;
            }
        }

        Some(parent)
    }
}

impl From<BranchChangesType> for AggregationChangeType {
    fn from(change: BranchChangesType) -> Self {
        match change {
            BranchChangesType::MakeBlank => Self::MakeBlank,
            BranchChangesType::AppendNode => Self::AppendNode,
            BranchChangesType::UpdateKey => Self::UpdateKey,
        }
    }
}

impl Display for AggregationChangeType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AggregationChangeType::UpdateKey => write!(f, "UpdateKey"),
            AggregationChangeType::MakeBlank => write!(f, "MakeBlank"),
            AggregationChangeType::MakeBlankThenAppendMember => {
                write!(f, "MakeBlankThenAppendMember")
            }
            AggregationChangeType::AppendNode => write!(f, "AppendNode"),
            AggregationChangeType::AppendMemberThenUpdateKey => {
                write!(f, "AppendMemberThenUpdateKey")
            }
            AggregationChangeType::UpdateKeyThenAppendMember => {
                write!(f, "UpdateKeyThenAppendMember")
            }
        }
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

/// BranchChangesIter iterates over branch changes provided by the aggregation.
impl<'a, D> BranchChangesIter<'a, D>
where
    D: RelatedData + Clone + Default,
{
    pub fn new(root: &'a ChangeAggregation<D>) -> Self {
        Self {
            inner_iter: AggregationNodeIterWithPath::new(root),
        }
    }

    fn parse_key_update<G>(
        item: &ChangeAggregation<D>,
        path: &Vec<(&ChangeAggregation<D>, Direction)>,
    ) -> BranchChanges<G>
    where
        D: HasPublicKey<G> + HasChangeTypeHint,
        G: AffineRepr,
    {
        let mut path_to_item = vec![];
        let mut public_keys = vec![];
        for (node, dir) in path {
            path_to_item.push(*dir);
            public_keys.push(node.data.get_public_key());
        }

        if let Some(node) = item.children.get_left()
            && node
                .data
                .get_change_type()
                .contains(&BranchChangesTypeHint::AppendNodeFix)
        {
            public_keys.push(node.data.get_public_key());
        } else {
            public_keys.push(item.data.get_public_key());
        }

        BranchChanges {
            change_type: BranchChangesType::UpdateKey,
            public_keys,
            node_index: NodeIndex::from(path_to_item),
        }
    }

    fn parse_make_blank<G>(
        item: &ChangeAggregation<D>,
        path: &Vec<(&ChangeAggregation<D>, Direction)>,
    ) -> BranchChanges<G>
    where
        D: HasPublicKey<G> + HasChangeTypeHint,
        G: AffineRepr,
    {
        let mut path_to_item = vec![];
        let mut public_keys = vec![];
        for (node, dir) in path {
            path_to_item.push(*dir);
            public_keys.push(node.data.get_public_key());
        }

        if let Some(node) = item.children.get_left()
            && node
                .data
                .get_change_type()
                .contains(&BranchChangesTypeHint::AppendNodeFix)
        {
            public_keys.push(node.data.get_public_key());
        } else {
            public_keys.push(item.data.get_public_key());
        }

        BranchChanges {
            change_type: BranchChangesType::MakeBlank,
            public_keys,
            node_index: NodeIndex::from(path_to_item),
        }
    }

    fn parse_append_node<G>(
        item: &ChangeAggregation<D>,
        path: &Vec<(&ChangeAggregation<D>, Direction)>,
    ) -> BranchChanges<G>
    where
        D: HasPublicKey<G> + HasChangeTypeHint,
        G: AffineRepr,
    {
        let mut path_to_item = vec![];
        let mut public_keys = vec![];
        for (node, dir) in path {
            path_to_item.push(*dir);
            public_keys.push(node.data.get_public_key());
        }
        public_keys.push(item.data.get_public_key());

        BranchChanges {
            change_type: BranchChangesType::AppendNode,
            public_keys,
            node_index: NodeIndex::from(path_to_item),
        }
    }

    fn parse_replace_node<G>(
        item: &ChangeAggregation<D>,
        path: &Vec<(&ChangeAggregation<D>, Direction)>,
    ) -> BranchChanges<G>
    where
        D: HasPublicKey<G> + HasChangeTypeHint,
        G: AffineRepr,
    {
        let mut path_to_item = vec![];
        let mut public_keys = vec![];
        for (node, dir) in path {
            path_to_item.push(*dir);
            public_keys.push(node.data.get_public_key());
        }

        if let Some(node) = item.children.get_left()
            && node
                .data
                .get_change_type()
                .contains(&BranchChangesTypeHint::AppendNodeFix)
        {
            public_keys.push(node.data.get_public_key());
        } else {
            public_keys.push(item.data.get_public_key());
        }

        BranchChanges {
            change_type: BranchChangesType::AppendNode,
            public_keys,
            node_index: NodeIndex::from(path_to_item),
        }
    }
}

// impl<'a, G> Iterator for BranchChangesIter<'a, ProverAggregationData<G>>
// where
//     G: AffineRepr,
// {
//     // type Item = (&'a ProverAggregation<G>, Vec<(&'a ProverAggregation<G>, Direction)>);
//     type Item = Vec<BranchChanges<G>>;
//
//     fn next(&mut self) -> Option<Self::Item> {
//         while let Some((item, path)) = self.inner_iter.next() {
//             if item.children.is_leaf() {
//                 let mut path_to_leaf = vec![];
//                 let mut public_keys = vec![];
//
//                 for (node, dir) in &path {
//                     path_to_leaf.push(*dir);
//                     public_keys.push(node.data.public_key);
//                 }
//
//                 public_keys.push(item.data.public_key);
//                 let leaf_index = NodeIndex::from(path_to_leaf);
//
//                 let mut branch_changes = Vec::new();
//                 if let Some((node, _)) = path.last() {
//                     for change_type in &node.data.change_type {
//                         branch_changes.push(BranchChanges {
//                             change_type: *change_type,
//                             public_keys: public_keys.clone(),
//                             node_index: leaf_index.clone(),
//                         })
//                     }
//                 }
//
//                 return Some(branch_changes);
//             }
//         }
//
//         None
//     }
// }

impl<'a, G> Iterator for BranchChangesIter<'a, VerifierAggregationData<G>>
where
    G: AffineRepr,
{
    // type Item = (&'a ProverAggregation<G>, Vec<(&'a ProverAggregation<G>, Direction)>);
    type Item = Vec<BranchChanges<G>>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some((item, path)) = self.inner_iter.next() {
            if !item.data.change_type.is_empty() {
                let mut branch_changes = Vec::new();
                debug!("item.data.change_type: {:?}", item.data.change_type);
                for change_type in &item.data.change_type {
                    branch_changes.push(match change_type {
                        BranchChangesTypeHint::AppendNodeFix => {
                            continue;
                        }
                        BranchChangesTypeHint::UpdateKey => Self::parse_key_update(item, &path),
                        BranchChangesTypeHint::MakeBlank { .. } => {
                            Self::parse_make_blank(item, &path)
                        }
                        BranchChangesTypeHint::AppendNode { extend } => {
                            let mut branch_change = if *extend {
                                let mut branch_change = Self::parse_append_node(item, &path);
                                // Add new node to change
                                let new_public_key = item.children.get_right()?.data.public_key;
                                branch_change.public_keys.push(new_public_key);
                                branch_change.node_index.push(Direction::Right);

                                branch_change
                            } else {
                                Self::parse_replace_node(item, &path)
                            };

                            branch_change
                        }
                    })
                }

                return Some(branch_changes);
            }
        }
        None
    }
}

impl Default for AggregationChangeType {
    fn default() -> Self {
        Self::UpdateKey
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
            latest: prover_data.latest,
            change_type: prover_data.change_type,
        }
    }
}

impl<G> TryFrom<ChangeAggregation<ProverAggregationData<G>>>
    for ChangeAggregation<VerifierAggregationData<G>>
where
    G: AffineRepr,
{
    type Error = ARTError;

    fn try_from(
        prover_aggregation: ChangeAggregation<ProverAggregationData<G>>,
    ) -> Result<Self, Self::Error> {
        let mut iter = AggregationNodeIterWithPath::new(&prover_aggregation);
        let (node, _) = iter.next().ok_or(ARTError::EmptyART)?;

        let verifier_data = VerifierAggregationData::<G>::from(node.data.clone());
        let mut verifier_aggregation = ChangeAggregation {
            children: Children::Leaf,
            data: verifier_data,
            marker: Default::default(),
        };

        for (node, path) in iter {
            let mut node_path = path.iter().copied().map(|(_, dir)| dir).collect::<Vec<_>>();
            if let Some(last_dir) = node_path.pop() {
                let verifier_data = VerifierAggregationData::<G>::from(node.data.clone());
                let next_node = ChangeAggregation {
                    children: Children::Leaf,
                    data: verifier_data,
                    marker: Default::default(),
                };

                if let Some(child) = verifier_aggregation.get_mut_child_at(&*node_path) {
                    child.children.set_child(last_dir, next_node);
                }
            }
        }

        Ok(verifier_aggregation)
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
            pk_marker, co_pk_marker, sk_marker, self.change_type
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
            pk_marker, co_pk_marker, self.change_type
        )
    }
}
