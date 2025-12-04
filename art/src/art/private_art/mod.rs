use crate::art::art_advanced_operations::ArtAdvancedOps;
use crate::art::public_art::PublicArtApplySnapshot;
use crate::art::{
    AggregationContext, ArtLevel, ProverArtefacts, PublicArt, PublicArtPreview, PublicMergeData,
};
use crate::art_node::{ArtNode, ArtNodeData, BinaryTree, LeafStatus, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{AggregatedChange, AggregationData, PrivateAggregatedChange};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zrt_zk::aggregated_art::VerifierAggregationTree;
use zrt_zk::art::{ProverNodeData, VerifierNodeData};

#[cfg(test)]
pub(crate) mod tests;

/// Describes secret key state after commit.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct ArtSecretPreview<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    strong_key: Option<G::ScalarField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    weak_key: Option<G::ScalarField>,
}

impl<G> ArtSecretPreview<G>
where
    G: AffineRepr,
{
    pub fn new(strong_key: Option<G::ScalarField>, weak_key: Option<G::ScalarField>) -> Self {
        Self {
            strong_key,
            weak_key,
        }
    }

    /// Return preview of the secret. Required current `key`
    pub fn preview(&self, key: G::ScalarField) -> G::ScalarField {
        let mut new_sk = self.strong_key.clone().unwrap_or(key);

        if let Some(weak_key) = self.weak_key {
            new_sk += weak_key;
        }

        new_sk
    }

    pub fn update(&mut self, secret: G::ScalarField, weak_only: bool) {
        if weak_only || self.strong_key.is_some() {
            match self.weak_key {
                None => self.weak_key = Some(secret),
                Some(current_weak_key) => self.weak_key = Some(current_weak_key + secret),
            }
        } else {
            self.strong_key = Some(secret)
        }
    }
}

/// Describes secret key state after commit.
#[derive(Debug, Default, Deserialize, Serialize, Clone, PartialEq)]
pub struct ArtSecretPreviewExcess<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    strong_key: G::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    weak_key: Option<G::ScalarField>,
}

impl<G> ArtSecretPreviewExcess<G>
where
    G: AffineRepr,
{
    pub fn new(strong_key: G::ScalarField, weak_key: Option<G::ScalarField>) -> Self {
        Self {
            strong_key,
            weak_key,
        }
    }

    pub fn preview(&self) -> G::ScalarField {
        let mut new_sk = self.strong_key;

        if let Some(weak_key) = self.weak_key {
            new_sk += weak_key;
        }

        new_sk
    }

    pub fn update(&mut self, secret: G::ScalarField) {
        match self.weak_key {
            None => self.weak_key = Some(secret),
            Some(current_weak_key) => self.weak_key = Some(current_weak_key + secret),
        }
    }
}

/// Merge context for ART branch secrets.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct ArtSecrets<G: AffineRepr> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    secrets: Vec<G::ScalarField>,
    secrets_preview: Vec<ArtSecretPreview<G>>,
    secrets_preview_excess: Vec<ArtSecretPreviewExcess<G>>,
}

impl<G> ArtSecrets<G>
where
    G: AffineRepr,
{
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    pub fn leaf(&self) -> G::ScalarField {
        self.secrets[self.secrets.len() - 1]
    }

    pub fn secret(&self, i: usize) -> Option<G::ScalarField> {
        self.secrets.get(i).map(|s| *s)
    }

    pub fn secrets(&self) -> &Vec<G::ScalarField> {
        &self.secrets
    }

    pub fn root(&self) -> G::ScalarField {
        self.secrets[0]
    }

    pub fn commit(&mut self) -> Result<(), ArtError> {
        for (sk, preview) in self.secrets.iter_mut().zip(self.secrets_preview.iter()) {
            *sk = preview.preview(*sk);
        }

        for sk in self.secrets_preview_excess.iter() {
            self.secrets.push(sk.preview());
        }

        self.secrets_preview.clear();
        self.secrets_preview_excess.clear();

        Ok(())
    }

    pub fn discard(&mut self) {
        self.secrets_preview.clear();
        self.secrets_preview_excess.clear();
    }

    /// Takes secrets of nodes on path from some node to the root, and updates it, starting
    /// from the root node.
    pub fn update<'a>(
        &mut self,
        new_secrets: impl IntoIterator<Item = &'a G::ScalarField>,
        weak_only: bool,
    ) -> Result<(), ArtError> {
        let mut new_secrets_iterator = new_secrets.into_iter();

        for (i, sk) in new_secrets_iterator
            .by_ref()
            .take(self.secrets.len())
            .enumerate()
        {
            if let Some(sk_preview) = self.secrets_preview.get_mut(i) {
                sk_preview.update(*sk, weak_only);
            } else {
                self.secrets_preview.push(ArtSecretPreview::default());
                self.secrets_preview[i].update(*sk, weak_only);
            }
        }

        for (i, sk) in new_secrets_iterator.enumerate() {
            if let Some(sk_excess_preview) = self.secrets_preview_excess.get_mut(i) {
                sk_excess_preview.update(*sk)
            } else {
                if weak_only {
                    return Err(ArtError::InvalidInput);
                }

                self.secrets_preview_excess
                    .push(ArtSecretPreviewExcess::new(*sk, None))
            }
        }

        Ok(())
    }

    pub fn preview<'a>(&'a self) -> ArtSecretsPreview<'a, G> {
        ArtSecretsPreview::new(self)
    }
}

impl<G> TryFrom<Vec<G::ScalarField>> for ArtSecrets<G>
where
    G: AffineRepr,
{
    type Error = ArtError;

    fn try_from(secrets: Vec<G::ScalarField>) -> Result<Self, Self::Error> {
        if secrets.is_empty() {
            return Err(ArtError::InvalidInput);
        }

        Ok(Self {
            secrets: secrets.into_iter().collect::<Vec<_>>(),
            secrets_preview: vec![],
            secrets_preview_excess: vec![],
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ArtSecretsPreview<'a, G: AffineRepr> {
    art_secrets: &'a ArtSecrets<G>,
}

impl<'a, G: AffineRepr> ArtSecretsPreview<'a, G> {
    pub fn new(art_secrets: &'a ArtSecrets<G>) -> Self {
        Self { art_secrets }
    }

    pub fn len(&self) -> usize {
        self.art_secrets.secrets_preview.len() + self.art_secrets.secrets_preview_excess.len()
    }

    pub fn leaf(&self) -> G::ScalarField {
        let excess_len = self.art_secrets.secrets_preview_excess.len();
        if excess_len.is_zero() {
            let last_index = self.art_secrets.secrets.len() - 1;
            if let Some(sk_preview) = self.art_secrets.secrets_preview.get(last_index) {
                sk_preview.preview(self.art_secrets.secrets[last_index])
            } else {
                self.art_secrets.leaf()
            }
        } else {
            self.art_secrets.secrets_preview_excess[excess_len - 1].preview()
        }
    }

    pub fn secret(&self, i: usize) -> Option<G::ScalarField> {
        let secrets_len = self.art_secrets.secrets_preview.len();
        if i < secrets_len {
            if let Some(sk_preview) = self.art_secrets.secrets_preview.get(i) {
                Some(sk_preview.preview(self.art_secrets.secrets[i]))
            } else {
                None
            }
        } else {
            self.art_secrets
                .secrets_preview_excess
                .get(i - secrets_len)
                .map(|s| s.preview())
        }
    }

    pub fn root(&self) -> G::ScalarField {
        if let Some(root_preview) = self.art_secrets.secrets_preview_excess.get(0) {
            root_preview.preview()
        } else {
            if let Some(root_preview) = self.art_secrets.secrets_preview.get(0) {
                root_preview.preview(self.art_secrets.secrets[0])
            } else {
                self.art_secrets.secrets[0]
            }
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ArtNodeIndex {
    /// Index of a user leaf.
    pub(crate) node_index: NodeIndex,

    /// Index of a user leaf in merge_tree.
    pub(crate) node_index_preview: Option<NodeIndex>,
}

impl ArtNodeIndex {
    pub fn new(node_index: NodeIndex, merge_node_index: Option<NodeIndex>) -> Self {
        Self {
            node_index,
            node_index_preview: merge_node_index,
        }
    }

    pub fn commit(&mut self) {
        if let Some(merge_node_index) = self.node_index_preview.take() {
            self.node_index = merge_node_index
        }
    }

    pub fn discard(&mut self) {
        self.node_index_preview = None;
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    pub fn node_index_preview(&self) -> &NodeIndex {
        match &self.node_index_preview {
            Some(index) => index,
            None => self.node_index(),
        }
    }

    /// Update node index by adding provided `direction` to the end of the path.
    pub fn push(&mut self, direction: Direction) {
        if let Some(index) = &mut self.node_index_preview {
            index.push(direction)
        } else {
            let mut index = self.node_index().clone();
            index.push(direction);
            self.node_index_preview = Some(index);
        }
    }
}

impl<T> From<T> for ArtNodeIndex
where
    NodeIndex: From<T>,
{
    fn from(value: T) -> Self {
        Self::new(NodeIndex::from(value), None)
    }
}

/// ART structure, which stores and operates with some user secrets. Wrapped around `PublicArt`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct PrivateArt<G>
where
    G: AffineRepr,
{
    /// Public part of the art.
    pub(crate) public_art: PublicArt<G>,

    /// Set of secret keys on path from the user leaf to the root.
    pub(crate) secrets: ArtSecrets<G>,

    /// Index of a user leaf.
    pub(crate) node_index: ArtNodeIndex,
}

/// The state of uncommited part of `PrivateArt` tree.
pub struct PrivateArtApplySnapshot<G: AffineRepr> {
    public_art_snapshot: PublicArtApplySnapshot<G>,
    secrets_snapshot: Vec<ArtSecretPreview<G>>,
    secrets_preview_excess: Vec<ArtSecretPreviewExcess<G>>,
    node_index_snapshot: Option<NodeIndex>,
}

impl<G: AffineRepr> PrivateArtApplySnapshot<G> {
    pub fn new(
        public_art_snapshot: PublicArtApplySnapshot<G>,
        secrets_snapshot: Vec<ArtSecretPreview<G>>,
        secrets_preview_excess: Vec<ArtSecretPreviewExcess<G>>,
        node_index_snapshot: Option<NodeIndex>,
    ) -> Self {
        Self {
            public_art_snapshot,
            secrets_snapshot,
            secrets_preview_excess,
            node_index_snapshot,
        }
    }
}

impl<G> PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    /// Create new ART tree with given secrets as leaves secrets. Return art with the left most
    /// secret as own.
    pub fn setup(secrets: &[G::ScalarField]) -> Result<Self, ArtError> {
        if secrets.is_empty() {
            return Err(ArtError::InvalidInput);
        }

        let mut level_nodes = Vec::with_capacity(secrets.len());
        let mut level_secrets = secrets.to_vec();

        // Process leaves of the tree
        for leaf_secret in secrets {
            let public_key = G::generator().mul(leaf_secret).into_affine();
            let leaf_data = ArtNodeData::new_leaf(public_key, LeafStatus::Active, vec![]);
            level_nodes.push(Box::new(ArtNode::new_leaf(leaf_data)));
        }

        // Fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets)?;
        }

        let (root, _) = Self::compute_root_node_from_leaves(level_nodes, &mut level_secrets)?;

        let public_art = PublicArt::from(root.as_ref().to_owned());

        let sk = *secrets.first().ok_or(ArtError::EmptyArt)?;
        let pk = G::generator().mul(sk).into_affine();
        let path = public_art.root().path_to_leaf_with(pk)?;
        let co_path = public_art.co_path(&path)?;
        let artefacts = recompute_artefacts(sk, &co_path)?;
        let secrets =
            ArtSecrets::try_from(artefacts.secrets.iter().rev().cloned().collect::<Vec<_>>())?;

        Ok(Self {
            public_art,
            secrets,
            node_index: ArtNodeIndex::from(NodeIndex::from(path).as_index()?),
        })
    }

    // Create new `PrivateArt` from `public_art` and user leaf `secret_key`.
    pub fn new(public_art: PublicArt<G>, secret_key: G::ScalarField) -> Result<Self, ArtError> {
        let leaf_path = public_art
            .root()
            .path_to_leaf_with(G::generator().mul(secret_key).into_affine())?;
        let co_path = public_art.co_path(&leaf_path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;
        let secrets =
            ArtSecrets::try_from(artefacts.secrets.iter().rev().cloned().collect::<Vec<_>>())?;
        let node_index = ArtNodeIndex::from(NodeIndex::from(leaf_path).as_index()?);

        Ok(Self {
            public_art,
            secrets,
            node_index,
        })
    }

    /// Create new `PrivateArt` from `public_art` and all the `secrets` on path from the
    /// user leaf to root.
    pub fn restore(public_art: PublicArt<G>, secrets: ArtSecrets<G>) -> Result<Self, ArtError> {
        let pk = G::generator().mul(secrets.leaf()).into_affine();
        let path = public_art.root().path_to_leaf_with(pk)?;
        Ok(Self {
            public_art,
            secrets,
            node_index: ArtNodeIndex::from(NodeIndex::from(path).as_index()?),
        })
    }

    pub fn apply<C, R>(&mut self, change: &C) -> Result<R, ArtError>
    where
        C: ApplicableChange<Self, R>,
    {
        change.apply(self)
    }

    /// Returns helper data with current merge configuration. Can be used to revert change
    /// applications after last `commit()`.
    pub fn snapshot(&self) -> PrivateArtApplySnapshot<G> {
        PrivateArtApplySnapshot::new(
            self.public_art.snapshot(),
            self.secrets.secrets_preview.clone(),
            self.secrets.secrets_preview_excess.clone(),
            self.node_index.node_index_preview.clone(),
        )
    }

    /// Return merge configuration fo the state specified in provided `snapshot`.
    pub fn undo_apply(&mut self, snapshot: PrivateArtApplySnapshot<G>) {
        self.public_art.undo_apply(snapshot.public_art_snapshot);
        self.secrets.secrets_preview = snapshot.secrets_snapshot;
        self.secrets.secrets_preview_excess = snapshot.secrets_preview_excess;
        self.node_index.node_index_preview = snapshot.node_index_snapshot;
    }

    /// Update art with all the stored epoch changes. removes all the merge data.
    pub fn commit(&mut self) -> Result<(), ArtError> {
        let reserve_clone = self.clone();

        self.commit_without_rollback()
            .inspect_err(|_| *self = reserve_clone)
    }

    fn commit_without_rollback(&mut self) -> Result<(), ArtError> {
        self.public_art.commit()?;
        self.secrets.commit()?;
        self.node_index.commit();

        Ok(())
    }

    /// Clears current merge state without commiting.
    pub fn discard(&mut self) {
        self.public_art.discard();
        self.node_index.discard();
        self.secrets.discard();
    }

    pub fn node_index(&self) -> &NodeIndex {
        self.node_index.node_index()
    }

    pub fn node_index_preview(&self) -> &NodeIndex {
        self.node_index.node_index_preview()
    }

    pub fn secrets(&self) -> &ArtSecrets<G> {
        &self.secrets
    }

    pub fn public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    pub fn root_secret_key(&self) -> G::ScalarField {
        self.secrets.root()
    }

    pub fn root_public_key(&self) -> G {
        G::generator().mul(self.root_secret_key()).into_affine()
    }

    pub fn leaf_secret_key(&self) -> G::ScalarField {
        self.secrets.leaf()
    }

    pub fn leaf_public_key(&self) -> G {
        G::generator().mul(self.leaf_secret_key()).into_affine()
    }

    /// Computes the ART assuming that `level_nodes` and `level_secrets` are a power of two. If
    /// they are not they can be lifted with `fit_leaves_in_one_level` method.
    fn compute_root_node_from_leaves(
        level_nodes: Vec<Box<ArtNode<G>>>,
        level_secrets: &mut [G::ScalarField],
    ) -> Result<(Box<ArtNode<G>>, G::ScalarField), ArtError> {
        let mut stack = Vec::with_capacity(level_nodes.len());

        let mut last_secret = G::ScalarField::zero();

        // stack contains node, and her conditional weight
        stack.push((level_nodes[0].clone(), 1));
        for (sk, node) in level_secrets.iter().zip(level_nodes).skip(1) {
            let mut right_node = node;
            let mut right_secret = *sk;
            let mut right_weight = 1;

            while let Some((left_node, left_weight)) = stack.pop() {
                if left_weight != right_weight {
                    // return the node bask and wait for it to be the same weight
                    stack.push((left_node, left_weight));
                    break;
                }

                let ark_common_secret = iota_function(
                    &left_node
                        .data()
                        .public_key()
                        .mul(right_secret)
                        .into_affine(),
                )?;
                right_secret = ark_common_secret;
                last_secret = ark_common_secret;

                let weight = left_node.data().weight() + right_node.data().weight();
                let public_key = G::generator().mul(&ark_common_secret).into_affine();
                right_node = Box::new(ArtNode::full_node(
                    ArtNodeData::new_internal(public_key, weight),
                    left_node,
                    right_node,
                ));
                right_weight += left_weight;
            }

            // put the node to the end of stack
            stack.push((right_node, right_weight));
        }

        let (root, _) = stack.pop().ok_or(ArtError::ArtLogic)?;

        Ok((root, last_secret))
    }

    fn fit_leaves_in_one_level(
        mut level_nodes: Vec<Box<ArtNode<G>>>,
        mut level_secrets: Vec<G::ScalarField>,
    ) -> Result<ArtLevel<G>, ArtError> {
        let mut level_size = 2;
        while level_size < level_nodes.len() {
            level_size <<= 1;
        }

        if level_size == level_nodes.len() {
            return Ok((level_nodes, level_secrets));
        }

        let excess = level_size - level_nodes.len();

        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();
        for _ in 0..(level_nodes.len() - excess) >> 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = iota_function(
                &left_node
                    .data()
                    .public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

            let weight = left_node.data().weight() + right_node.data().weight();
            let public_key = G::generator().mul(&common_secret).into_affine();
            let node = ArtNode::full_node(
                ArtNodeData::new_internal(public_key, weight),
                left_node,
                right_node,
            );

            upper_level_nodes.push(Box::new(node));
            upper_level_secrets.push(common_secret);
        }

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    pub fn preview(&self) -> PublicArtPreview<G> {
        self.public_art.preview()
    }

    pub(crate) fn update_node_key_change(
        &mut self,
        new_key: G::ScalarField,
        target_leaf_path: &[Direction],
    ) -> Result<(ProverArtefacts<G>, BranchChange<G>), ArtError> {
        let mut co_path = self.preview().co_path(&target_leaf_path)?;

        let artefacts = recompute_artefacts(new_key, &co_path)?;

        let change = artefacts.derive_branch_change(
            BranchChangeType::UpdateKey,
            NodeIndex::from(NodeIndex::get_index_from_path(target_leaf_path)?),
        )?;

        Ok((artefacts, change))
    }

    pub(crate) fn insert_or_extend_node_change(
        &mut self,
        new_key: G::ScalarField,
        target_leaf_path: &[Direction],
    ) -> Result<(ProverArtefacts<G>, BranchChange<G>), ArtError> {
        let mut co_path = Vec::new();

        let target_node = self.preview().root().node_at(&target_leaf_path)?;
        match target_node.status() {
            None => return Err(ArtError::LeafOnly),
            Some(LeafStatus::Active) | Some(LeafStatus::PendingRemoval) => {
                co_path.push(target_node.public_key())
            }
            _ => {}
        }

        co_path.append(&mut self.preview().co_path(&target_leaf_path)?);

        let artefacts = recompute_artefacts(new_key, &co_path)?;

        let change = artefacts.derive_branch_change(
            BranchChangeType::AddMember,
            NodeIndex::from(NodeIndex::get_index_from_path(target_leaf_path)?),
        )?;

        Ok((artefacts, change))
    }

    pub(crate) fn find_place_for_new_node(&self) -> Result<Vec<Direction>, ArtError> {
        match self.find_path_to_left_most_blank_node() {
            Some(path) => Ok(path),
            None => self.find_path_to_lowest_leaf(),
        }
    }

    /// Searches for the left most blank node and returns the vector of directions to it.
    pub(crate) fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in self.root().leaf_iter_with_path() {
            if node.is_leaf() && !matches!(node.data().status(), Some(LeafStatus::Active)) {
                let mut node_path = Vec::with_capacity(path.len());

                for (_, dir) in path {
                    node_path.push(dir);
                }

                return Some(node_path);
            }
        }

        None
    }

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left branch.
    pub(crate) fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ArtError> {
        let mut candidate = self.root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate
                .child(Direction::Left)
                .ok_or(ArtError::PathNotExists)?;
            let r = candidate
                .child(Direction::Right)
                .ok_or(ArtError::PathNotExists)?;

            let next_direction = match l.data().weight() <= r.data().weight() {
                true => Direction::Left,
                false => Direction::Right,
            };

            next.push(next_direction);
            candidate = candidate
                .child(next_direction)
                .ok_or(ArtError::InvalidInput)?;
        }

        while let ArtNode {
            l: Some(l),
            r: Some(r),
            ..
        } = candidate
        {
            if l.data().weight() <= r.data().weight() {
                next.push(Direction::Left);
                candidate = l;
            } else {
                next.push(Direction::Right);
                candidate = r;
            }
        }

        Ok(next)
    }

    pub fn verification_branch(
        &self,
        change: &BranchChange<G>,
    ) -> Result<Vec<VerifierNodeData<G>>, ArtError> {
        self.public_art.verification_branch(change)
    }

    pub fn verification_tree(
        &self,
        change: &AggregatedChange<G>,
    ) -> Result<VerifierAggregationTree<G>, ArtError> {
        self.public_art.verification_tree(change)
    }
}

impl<G> BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub(crate) fn private_art_secrets_unrecoverable_apply(
        &self,
        art: &mut PrivateArt<G>,
        weak_only: bool,
    ) -> Result<G::ScalarField, ArtError> {
        let intersection = self.node_index.intersect_with(art.node_index())?;
        let target_node = art.node_at(&intersection)?;
        let mut use_all_secrets = false;
        let add_co_path_from_change =
            if matches!(self.change_type, BranchChangeType::AddMember) && target_node.is_leaf() {
                match target_node.data().status() {
                    None => return Err(ArtError::ArtLogic),
                    Some(LeafStatus::Blank) => false,
                    _ => {
                        art.node_index.push(Direction::Left);
                        use_all_secrets = true;

                        true
                    }
                }
            } else {
                true
            };

        let mut co_path = Vec::new();

        if add_co_path_from_change {
            co_path.push(
                *self
                    .public_keys
                    .get(intersection.len() + 1)
                    .ok_or(ArtError::InvalidInput)?,
            );
        }
        co_path.append(&mut art.public_art().co_path(&intersection)?);

        let level_sk = art
            .secrets
            .secret(intersection.len() + 1)
            .unwrap_or(art.leaf_secret_key());
        // .ok_or(ArtError::InvalidBranchChange)?;
        let artefacts = recompute_artefacts(level_sk, &co_path)?;

        if use_all_secrets {
            art.secrets
                .update(artefacts.secrets.iter().rev(), weak_only)?;
        } else {
            art.secrets
                .update(artefacts.secrets[1..].iter().rev(), weak_only)?;
        }

        Ok(*artefacts
            .secrets
            .last()
            .ok_or(ArtError::InvalidBranchChange)?)
    }

    pub(crate) fn private_art_unrecoverable_apply(
        &self,
        art: &mut PrivateArt<G>,
        weak_only: bool,
    ) -> Result<G::ScalarField, ArtError> {
        self.pub_art_unrecoverable_apply(&mut art.public_art)?;
        let tk = self.private_art_secrets_unrecoverable_apply(art, weak_only)?;

        Ok(tk)
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        if art.node_index().is_subpath_of(&self.node_index)? {
            match self.change_type {
                BranchChangeType::RemoveMember => return Err(ArtError::InapplicableBlanking),
                BranchChangeType::UpdateKey => return Err(ArtError::InapplicableKeyUpdate),
                BranchChangeType::Leave => return Err(ArtError::InapplicableLeave),
                BranchChangeType::AddMember => {}
            }
        }

        let (weak_only, _) = self.pub_art_apply_prepare(art.public_art())?;

        let snapshot = art.snapshot();

        match self.private_art_unrecoverable_apply(art, weak_only) {
            Err(err) => {
                art.undo_apply(snapshot);
                Err(err)
            }
            Ok(tk) => Ok(tk),
        }
    }
}

impl<G, S> ApplicableChange<PrivateArt<G>, G::ScalarField> for S
where
    S: PrimeField,
    G: AffineRepr<ScalarField = S>,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        let snapshot = art.snapshot();

        match helper_tools::inner_apply_own_key_update(art, *self) {
            Err(err) => {
                art.undo_apply(snapshot);
                Err(err)
            }
            Ok(tk) => Ok(tk),
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        let snapshot = art.snapshot();

        match self.private_art_unrecoverable_apply(art) {
            Err(err) => {
                art.undo_apply(snapshot);
                Err(err)
            }
            Ok(tk) => Ok(tk),
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for PrivateAggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        let snapshot = art.snapshot();

        match {
            self.change()
                .pub_art_unrecoverable_apply(&mut art.public_art)?;
            self.change()
                .private_art_secrets_unrecoverable_apply(art, Some(self.key()))
        } {
            Err(err) => {
                art.undo_apply(snapshot);
                Err(err)
            }
            Ok(tk) => Ok(tk),
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for AggregationContext<PrivateArt<G>, G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        let aggregation = AggregatedChange::try_from(self)?;
        aggregation.apply(art)
    }
}

impl<G, S> ArtAdvancedOps<G, (S, BranchChange<G>)> for PrivateArt<G>
where
    S: Clone,
    G: AffineRepr<ScalarField = S>,
    G::BaseField: PrimeField,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        self.add_member(new_key).map(|(tk, change, _)| (tk, change))
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>), ArtError> {
        self.remove_member(target_leaf, new_key)
            .map(|(tk, change, _)| (tk, change))
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        self.leave_group(new_key)
            .map(|(tk, change, _)| (tk, change))
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        self.update_key(new_key).map(|(tk, change, _)| (tk, change))
    }
}

impl<G, S> ArtAdvancedOps<G, (S, BranchChange<G>, Vec<ProverNodeData<G>>)> for PrivateArt<G>
where
    S: Clone,
    G: AffineRepr<ScalarField = S>,
    G::BaseField: PrimeField,
{
    fn add_member(
        &mut self,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.preview().find_place_for_new_node()?;
        let (artefacts, change) = self.insert_or_extend_node_change(new_key, &path)?;
        let tk = artefacts
            .secrets
            .last()
            .cloned()
            .ok_or(ArtError::EmptyArt)?;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = target_leaf.get_path()?;

        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts
            .secrets
            .last()
            .cloned()
            .ok_or(ArtError::EmptyArt)?;
        change.change_type = BranchChangeType::RemoveMember;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn leave_group(
        &mut self,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.node_index_preview().get_path()?;

        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts
            .secrets
            .last()
            .cloned()
            .ok_or(ArtError::EmptyArt)?;
        change.change_type = BranchChangeType::Leave;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn update_key(
        &mut self,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.node_index_preview().get_path()?;
        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts
            .secrets
            .last()
            .cloned()
            .ok_or(ArtError::EmptyArt)?;
        change.change_type = BranchChangeType::UpdateKey;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }
}

impl<G> PartialEq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        if self.root() == other.root() && self.root_secret_key() == other.root_secret_key() {
            return true;
        }

        false
    }
}

impl<G> Eq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
}
