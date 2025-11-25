use crate::art::art_advanced_operations::ArtAdvancedOps;
use crate::art::artefacts::VerifierArtefacts;
use crate::art::{ArtLevel, ArtUpdateOutput, ProverArtefacts, PublicArt, PublicArtPreview};
use crate::art_node::{ArtNode, LeafIterWithPath, LeafStatus, NodeIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregationNode, AggregationNodeIterWithPath, AggregationTree, TreeIterHelper,
    TreeNodeIterWithPath,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
use crate::helper_tools;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::mem;
use std::ops::{Add, MulAssign};
use tracing::debug;
use cortado::{CortadoAffine, Parameters};
use zrt_zk::art::{ProverNodeData, VerifierNodeData};
use zrt_zk::EligibilityArtefact;

#[cfg(test)]
mod tests;

#[derive(Deserialize, Serialize, Clone, PartialEq, Default)]
pub struct ArtSecret<G>
where
    G: AffineRepr
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    key: G::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    weak_key: Option<G::ScalarField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    strong_key: Option<G::ScalarField>,
}

impl<G> ArtSecret<G>
where
    G: AffineRepr,
{
    pub fn key(&self) -> G::ScalarField {
        self.key
    }

    pub fn preview(&self) -> G::ScalarField {
        let mut new_sk = self.key;

        if let Some(strong_key) = self.strong_key {
            new_sk = strong_key;
        }

        if let Some(weak_key) = self.weak_key {
            new_sk += weak_key;
        }

        new_sk
    }

    pub fn commit(&mut self) {
        let mut new_sk = self.key;

        if let Some(strong_key) = self.strong_key {
            new_sk = strong_key;
            self.strong_key = None;
        }

        if let Some(weak_key) = self.weak_key {
            new_sk += weak_key;
            self.weak_key = None;
        }

        self.key = new_sk;
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

impl<G, S> From<S> for ArtSecret<G>
where
    G: AffineRepr<ScalarField = S>,
    S: PrimeField + Into<<S as PrimeField>::BigInt>,
{
    fn from(value: S) -> Self {
        Self {
            key: value,
            weak_key: None,
            strong_key: None,
        }
    }
}

impl<G> Debug for ArtSecret<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let weak_marker = if let Some(weak_key) = self.weak_key {
            format!("sk:{}, pk: {:?}", &weak_key, G::generator().mul(weak_key).into_affine().x())
        } else {
            "None".to_string()
        };

        let strong_marker = if let Some(strong_key) = self.strong_key {
            format!("sk:{}, pk: {:?}", &strong_key, G::generator().mul(strong_key).into_affine().x())
        } else {
            "None".to_string()
        };

        f.debug_struct("ArtSecret")
            .field("key         ",  &format!("sk:{}, pk: {:?}", &self.key, G::generator().mul(self.key).into_affine().x()))
            .field("preview key ",  &format!("sk:{}, pk: {:?}", &self.preview(), G::generator().mul(self.preview()).into_affine().x()))
            .field("weak_key    ",  &weak_marker)
            .field("strong_key  ",  &strong_marker)
            .finish()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct ArtSecrets<G>(Vec<ArtSecret<G>>)
where
    G: AffineRepr;

impl<G> ArtSecrets<G>
where
    G: AffineRepr,
{
    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn leaf(&self) -> &ArtSecret<G> {
        &self.0[self.0.len() - 1]
    }

    pub fn secret(&self, i: usize) -> Option<&ArtSecret<G>> {
        self.0.get(i)
    }

    pub fn secrets(&self) -> &Vec<ArtSecret<G>> {
        &self.0
    }

    pub fn root(&self) -> &ArtSecret<G> {
        &self.0[0]
    }

    pub fn extend_with(&mut self, sk: G::ScalarField) {
        self.0.push(ArtSecret::from(sk))
    }

    /// Returns secret keys on path from leaf node to the root node.
    pub fn secret_keys(&self) -> Vec<G::ScalarField> {
        let mut secrets = Vec::new();
        for secret in self.0.iter().rev() {
            secrets.push(secret.key());
        }

        secrets
    }

    pub fn commit(&mut self) {
        for secret in self.0.iter_mut() {
            secret.commit();
        }
    }

    /// Takes secrets of nodes on path from some node to the root, and updates it, starting
    /// from the root node
    pub fn update(
        &mut self,
        new_secrets: &[G::ScalarField],
        weak_only: bool,
    ) -> Result<(), ArtError> {
        for (i, secret) in new_secrets.iter().rev().enumerate() {
            self.0[i].update(*secret, weak_only);
        }

        Ok(())
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

        Ok(Self(
            secrets
                .into_iter()
                .rev()
                .map(|sk| ArtSecret::from(sk))
                .collect(),
        ))
    }
}


/// ART structure, which stores and operates with some user secrets. Wrapped around `PublicArt`.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct PrivateArt<G>
where
    G: AffineRepr,
{
    /// Public part of the art
    pub(crate) public_art: PublicArt<G>,

    /// Set of secret keys on path from the user leaf to the root.
    pub(crate) secrets: ArtSecrets<G>,

    /// Index of a user leaf.
    pub(crate) node_index: NodeIndex,
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
            level_nodes.push(Box::new(ArtNode::new_leaf(
                G::generator().mul(leaf_secret).into_affine(),
            )));
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

        Ok(Self {
            public_art,
            secrets: ArtSecrets::try_from(artefacts.secrets)?,
            node_index: NodeIndex::from(path),
        })
    }

    // Create new `PrivateArt` from `public_art` and user leaf `secret_key`.
    pub fn new(public_art: PublicArt<G>, secret_key: G::ScalarField) -> Result<Self, ArtError> {
        let leaf_path = public_art
            .root()
            .path_to_leaf_with(G::generator().mul(secret_key).into_affine())?;
        let co_path = public_art.co_path(&leaf_path)?;

        let artefacts = recompute_artefacts(secret_key, &co_path)?;

        Ok(Self {
            public_art,
            secrets: ArtSecrets::try_from(artefacts.secrets)?,
            node_index: NodeIndex::from(leaf_path).as_index()?,
        })
    }

    /// Create new `PrivateArt` from `public_art` and all the `secrets` on path from the
    /// user leaf to root.
    pub fn restore(
        public_art: PublicArt<G>,
        secrets: ArtSecrets<G>,
    ) -> Result<Self, ArtError> {
        let pk = G::generator()
            .mul(secrets.leaf().key())
            .into_affine();
        let path = public_art.root().path_to_leaf_with(pk)?;
        Ok(Self {
            public_art,
            secrets,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn apply<C, R>(&mut self, change: &C) -> Result<R, ArtError>
    where
        C: ApplicableChange<Self, R>,
    {
        change.apply(self)
    }

    pub fn commit(&mut self) -> Result<(), ArtError> {
        self.public_art.commit()?;
        self.secrets.commit();

        Ok(())
    }

    pub fn node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    pub fn secrets(&self) -> &ArtSecrets<G> {
        &self.secrets
    }

    pub fn public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    pub fn root_secret_key(&self) -> G::ScalarField {
        self.secrets.root().key()
    }

    pub fn root_public_key(&self) -> G {
        G::generator().mul(self.root_secret_key()).into_affine()
    }

    pub fn leaf_secret_key(&self) -> G::ScalarField {
        self.secrets.leaf().key()
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

                let ark_common_secret =
                    iota_function(&left_node.public_key().mul(right_secret).into_affine())?;
                right_secret = ark_common_secret;
                last_secret = ark_common_secret;

                right_node = Box::new(ArtNode::new_internal_node(
                    G::generator().mul(&ark_common_secret).into_affine(),
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
                    .public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

            let node = ArtNode::new_internal_node(
                G::generator().mul(&common_secret).into_affine(),
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

    pub(crate) fn preview(&self) -> PublicArtPreview<G> {
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
    fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in LeafIterWithPath::new(self.root()) {
            if node.is_leaf() && !matches!(node.status(), Some(LeafStatus::Active)) {
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
    fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ArtError> {
        let mut candidate = self.root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate
                .child(Direction::Left)
                .ok_or(ArtError::PathNotExists)?;
            let r = candidate
                .child(Direction::Right)
                .ok_or(ArtError::PathNotExists)?;

            let next_direction = match l.weight() <= r.weight() {
                true => Direction::Left,
                false => Direction::Right,
            };

            next.push(next_direction);
            candidate = candidate
                .child(next_direction)
                .ok_or(ArtError::InvalidInput)?;
        }

        while let ArtNode::Internal { l, r, .. } = candidate {
            if l.weight() <= r.weight() {
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
        changes: &BranchChange<G>,
    ) -> Result<Vec<VerifierNodeData<G>>, ArtError> {
        self.public_art.verification_branch(changes)
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
        // debug!("intersection: {intersection:#?}");
        let target_node = art.node_at(&intersection)?;
        let add_co_path_from_change =
            if matches!(self.change_type, BranchChangeType::AddMember) && target_node.is_leaf() {
                match target_node.status() {
                    None => return Err(ArtError::ArtLogic),
                    Some(LeafStatus::Blank) => false,
                    _ => {
                        art.secrets.extend_with(art.secrets.leaf().key());
                        art.node_index.push(Direction::Left);

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
        co_path.append(&mut art.public_art().co_path(&intersection).unwrap());

        let level_sk = art
            .secrets
            .secret(intersection.len() + 1)
            .ok_or(ArtError::InvalidBranchChange)?
            .key();
        let artefacts = recompute_artefacts(level_sk, &co_path)?;
        art.secrets
            .update(&artefacts.secrets[1..], weak_only)?;

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

        let merge_tree_reserve_copy = art.public_art().merge_tree.clone();

        match self.private_art_unrecoverable_apply(art, weak_only) {
            Err(err) => {
                art.public_art.merge_tree = merge_tree_reserve_copy;
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
        helper_tools::inner_apply_own_key_update(art, *self)
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
        self.remove_member(target_leaf, new_key).map(|(tk, change, _)| (tk, change))
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        self.leave_group(new_key).map(|(tk, change, _)| (tk, change))
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
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.find_place_for_new_node()?;
        let (artefacts, change) = self.insert_or_extend_node_change(new_key, &path)?;
        let tk = artefacts.secrets.last().cloned().ok_or(ArtError::EmptyArt)?;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = target_leaf.get_path()?;

        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts.secrets.last().cloned().ok_or(ArtError::EmptyArt)?;
        change.change_type = BranchChangeType::RemoveMember;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.node_index().get_path()?;

        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts.secrets.last().cloned().ok_or(ArtError::EmptyArt)?;
        change.change_type = BranchChangeType::Leave;

        Ok((tk, change, artefacts.to_prover_branch()?))
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>, Vec<ProverNodeData<G>>), ArtError> {
        let path = self.node_index().get_path()?;
        let (artefacts, mut change) = self.update_node_key_change(new_key, &path)?;
        let tk = artefacts.secrets.last().cloned().ok_or(ArtError::EmptyArt)?;
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
