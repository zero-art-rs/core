use crate::art::art_advanced_operations::ArtAdvancedOps;
use crate::art::artefacts::VerifierArtefacts;
use crate::art::{ArtLevel, ArtUpdateOutput, ProverArtefacts, PublicArt, PublicArtPreview};
use crate::art_node::{ArtNode, LeafIterWithPath, LeafStatus, NodeIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregationNode, AggregationNodeIterWithPath, AggregationTree, TreeIterHelper,
    TreeNodeIterWithPath,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem;
use std::ops::Add;
use tracing::debug;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
pub(crate) struct ArtSecret<G>
where
    G: AffineRepr,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) key: G::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) weak_key: Option<G::ScalarField>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub(crate) strong_key: Option<G::ScalarField>,
}

impl<G> ArtSecret<G>
where
    G: AffineRepr,
{
    fn from(value: G::ScalarField) -> Self {
        Self {
            key: value,
            weak_key: None,
            strong_key: None,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub(crate) struct ArtSecrets<G>(Vec<ArtSecret<G>>)
where
    G: AffineRepr;

impl<G> ArtSecrets<G>
where
    G: AffineRepr,
{
    pub fn leaf_key(&self) -> G::ScalarField {
        self.0[self.0.len() - 1].key
    }

    pub fn i_th_key_from_root(&self, i: usize) -> Option<G::ScalarField> {
        self.0.get(i).map(|record| record.key)
    }

    pub fn root_key(&self) -> G::ScalarField {
        self.0[0].key
    }

    pub fn extend_with(&mut self, sk: G::ScalarField) {
        self.0.push(ArtSecret::from(sk))
    }

    pub fn commited_secrets(&self) -> Vec<G::ScalarField> {
        let mut secrets = Vec::new();
        for secret in self.0.iter().rev() {
            secrets.push(secret.key);
        }

        secrets
    }

    pub fn commit(&mut self) {
        for secret in self.0.iter_mut() {
            let mut new_sk = *secret.strong_key.get_or_insert(secret.key);
            secret.strong_key = None;
            if let Some(weak_key) = secret.weak_key {
                new_sk += weak_key;
                secret.weak_key = None;
            }

            secret.key = new_sk
        }
    }

    fn update_secret(&mut self, i: usize, secret: G::ScalarField, weak_only: bool) {
        if weak_only || self.0[i].strong_key.is_some() {
            match self.0[i].weak_key {
                None => self.0[i].weak_key = Some(secret),
                Some(current_secret) => self.0[i].weak_key = Some(current_secret + secret),
            }
        } else {
            self.0[i].strong_key = Some(secret)
        }
    }

    /// Takes secrets of nodes on path from some node to the root
    pub(crate) fn update_from_root(
        &mut self,
        new_secrets: &[G::ScalarField],
        weak_only: bool,
    ) -> Result<(), ArtError> {
        for (i, secret) in new_secrets.iter().rev().enumerate() {
            self.update_secret(i, *secret, weak_only);
        }

        Ok(())
    }

    fn try_from_uprising_secrets(secrets: Vec<G::ScalarField>) -> Result<Self, ArtError> {
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
            secrets: ArtSecrets::try_from_uprising_secrets(artefacts.secrets)?,
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
            secrets: ArtSecrets::try_from_uprising_secrets(artefacts.secrets)?,
            node_index: NodeIndex::from(leaf_path).as_index()?,
        })
    }

    /// Create new `PrivateArt` from `public_art` and all the `secrets` on path from the
    /// user leaf to root.
    pub fn restore(
        public_art: PublicArt<G>,
        secrets: Vec<G::ScalarField>,
    ) -> Result<Self, ArtError> {
        let pk = G::generator()
            .mul(secrets.first().ok_or(ArtError::EmptyArt)?)
            .into_affine();
        let path = public_art.root().path_to_leaf_with(pk)?;
        Ok(Self {
            public_art,
            secrets: ArtSecrets::try_from_uprising_secrets(secrets)?,
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

    pub fn public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    pub fn mut_public_art(&mut self) -> &mut PublicArt<G> {
        &mut self.public_art
    }

    pub fn root_secret_key(&self) -> G::ScalarField {
        self.secrets.root_key()
    }

    pub fn root_public_key(&self) -> G {
        G::generator().mul(self.root_secret_key()).into_affine()
    }

    pub fn leaf_secret_key(&self) -> G::ScalarField {
        self.secrets.leaf_key()
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

    fn update_node_key_change(
        &mut self,
        new_key: G::ScalarField,
        target_leaf_path: &[Direction],
    ) -> Result<(G::ScalarField, BranchChange<G>), ArtError> {
        let mut co_path = self.preview().co_path(&target_leaf_path)?;

        let artefacts = recompute_artefacts(new_key, &co_path)?;

        let change = artefacts.derive_branch_change(
            BranchChangeType::UpdateKey,
            NodeIndex::from(NodeIndex::get_index_from_path(target_leaf_path)?),
        )?;
        let tk = *artefacts.secrets.last().ok_or(ArtError::EmptyArt)?;

        Ok((tk, change))
    }

    fn insert_or_extend_node_change(
        &mut self,
        new_key: G::ScalarField,
        target_leaf_path: &[Direction],
    ) -> Result<(G::ScalarField, BranchChange<G>), ArtError> {
        let mut co_path = self.preview().co_path(&target_leaf_path)?;

        let target_node = self.preview().root().node_at(&target_leaf_path)?;
        match target_node.status() {
            None => return Err(ArtError::LeafOnly),
            Some(LeafStatus::Active) | Some(LeafStatus::PendingRemoval) => {
                co_path.push(target_node.public_key())
            }
            _ => {}
        }

        co_path.reverse();

        let artefacts = recompute_artefacts(new_key, &co_path)?;

        let change = artefacts.derive_branch_change(
            BranchChangeType::AddMember,
            NodeIndex::from(NodeIndex::get_index_from_path(target_leaf_path)?),
        )?;
        let tk = *artefacts.secrets.last().ok_or(ArtError::EmptyArt)?;

        Ok((tk, change))
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
        let mut intersection = self.node_index.intersect_with(art.node_index())?;

        let target_node = art.node_at(&intersection)?;
        let add_co_path_from_change =
            if matches!(self.change_type, BranchChangeType::AddMember) && target_node.is_leaf() {
                match target_node.status() {
                    None => return Err(ArtError::ArtLogic),
                    Some(LeafStatus::Blank) => false,
                    _ => {
                        art.secrets.extend_with(art.secrets.leaf_key());
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

        // co_path.reverse();

        let level_sk = art
            .secrets
            .i_th_key_from_root(intersection.len() + 1)
            .ok_or(ArtError::InvalidBranchChange)?;
        let artefacts = recompute_artefacts(level_sk, &co_path)?;
        art.secrets
            .update_from_root(&artefacts.secrets, weak_only)?;

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

pub(crate) struct PrivateBranchChange<G: AffineRepr>(G::ScalarField, BranchChange<G>);

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for PrivateBranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        if matches!(self.1.change_type, BranchChangeType::UpdateKey)
            && self.1.node_index.eq(art.node_index())
        {
            helper_tools::inner_apply_own_key_update(art, self.0)
        } else {
            self.1.apply(art)
        }
    }
}

impl<G, S> ArtAdvancedOps<G, (S, BranchChange<G>)> for PrivateArt<G>
where
    G: AffineRepr<ScalarField = S>,
    G::BaseField: PrimeField,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        let path = self.find_place_for_new_node()?;
        self.insert_or_extend_node_change(new_key, &path)
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(S, BranchChange<G>), ArtError> {
        let path = target_leaf.get_path()?;

        let (tk, mut change) = self.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::RemoveMember;

        Ok((tk, change))
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        let path = self.node_index().get_path()?;

        let (tk, mut change) = self.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::Leave;

        Ok((tk, change))
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<(S, BranchChange<G>), ArtError> {
        let path = self.node_index().get_path()?;
        let (tk, mut change) = self.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::UpdateKey;

        Ok((tk, change))
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

#[cfg(test)]
mod tests {
    use crate::art::PrivateArt;
    use crate::art::PublicArt;
    use crate::art::art_advanced_operations::ArtAdvancedOps;
    use crate::art::private_art::PrivateBranchChange;
    use crate::art_node::{LeafIterWithPath, LeafStatus, TreeMethods};
    use crate::changes::ApplicableChange;
    use crate::errors::ArtError;
    use crate::node_index::{Direction, NodeIndex};
    use crate::test_helper_tools::init_tracing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::cmp::{max, min};
    use std::ops::Mul;
    use std::panic::panic_any;
    use tracing::{debug, info, warn};

    const TEST_GROUP_SIZE: usize = 20;

    #[test]
    /// Test if art serialization -> deserialization works correctly for unchanged arts
    fn test_public_art_initial_serialization() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);

        let secrets = (0..TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        for i in (1..TEST_GROUP_SIZE).step_by(7) {
            let private_art = PrivateArt::setup(&secrets[..i]).unwrap();
            let public_art_bytes = to_allocvec(&private_art.public_art()).unwrap();

            // Try to deserialize art for every other user in a group
            for j in 0..i {
                let deserialized_art: PrivateArt<CortadoAffine> =
                    PrivateArt::new(from_bytes(&public_art_bytes).unwrap(), secrets[j]).unwrap();

                assert_eq!(
                    deserialized_art,
                    private_art,
                    "Both users have the same view on the state of the art (size: {i}, user: {j}). Deserialized_art:\n{}\nPrivate_art\n{}\n\
                    deserialized_art.secrets: {:#?},\nprivate_art.secrets: {:#?}\n\
                    deserialized_art.leaf_secret: {:?},\nprivate_art.leaf_secret: {:?}",
                    deserialized_art.root(),
                    private_art.root(),
                    deserialized_art.secrets,
                    private_art.secrets,
                    secrets[0],
                    secrets[j]
                );
            }
        }
    }

    #[test]
    fn test_art_weight_balance_at_creation() {
        for i in 1..TEST_GROUP_SIZE {
            let mut rng = StdRng::seed_from_u64(0);
            let secrets = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
            let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

            let mut min_height = u64::MAX;
            let mut max_height = u64::MIN;
            let root = art.root();

            for (_, path) in LeafIterWithPath::new(root) {
                min_height = min(min_height, path.len() as u64);
                max_height = max(max_height, path.len() as u64);
            }

            assert!(max_height - min_height < 2);
        }
    }

    #[test]
    fn test_flow_append_join_update() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::setup(&vec![secret_key_0]).unwrap();
        assert_eq!(
            user0.leaf_public_key(),
            CortadoAffine::generator().mul(secret_key_0).into_affine(),
            "New node is in the art, and it is on the correct path.",
        );

        // Add member with user0
        let secret_key_1 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        let (_, change0) = user0.add_member(secret_key_1).unwrap();

        let tk = user0.apply(&change0).unwrap();
        user0.commit().unwrap();

        assert_eq!(user0.leaf_secret_key(), secret_key_0);
        assert_eq!(
            user0
                .node(&change0.node_index)
                .unwrap()
                .right()
                .unwrap()
                .public_key(),
            CortadoAffine::generator().mul(secret_key_1).into_affine(),
            "New node is in the art, and it is on the correct path.",
        );
        assert_eq!(
            user0.node(&user0.node_index()).unwrap().public_key(),
            CortadoAffine::generator().mul(secret_key_0).into_affine(),
            "User node is isn't changed, after append member operation.",
        );
        assert_ne!(
            user0.node(&change0.node_index).unwrap().public_key(),
            user0.node(&user0.node_index()).unwrap().public_key(),
            "Sanity check: Both users nodes have different public key.",
        );

        // Serialise and deserialize art for the new user.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        assert_ne!(secret_key_0, secret_key_1);
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        assert_eq!(public_art.root(), user0.root());

        let mut user1 = PrivateArt::new(public_art, secret_key_1).unwrap();
        assert_eq!(user1.leaf_secret_key(), secret_key_1);
        assert_eq!(user1.root_secret_key(), user0.root_secret_key());
        // info!("user1\n{}", user1.root());

        assert_ne!(
            user0.secrets, user1.secrets,
            "Sanity check: Both users have different path secrets"
        );
        assert_eq!(user0.root(), user1.root());
        assert_eq!(user0.root_secret_key(), user1.root_secret_key());
        assert!(user0.eq(&user1), "New user received the same art");
        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );

        let tk0 = user0.root_secret_key();
        let tk1 = user1.root_secret_key();

        let secret_key_3 = Fr::rand(&mut rng);

        // New user updates his key
        assert_ne!(secret_key_1, secret_key_3);
        let (tk2, change_key_update) = user1.update_key(secret_key_3).unwrap();
        // user1.apply(&change_key_update).unwrap();
        user1.apply(&secret_key_3).unwrap();
        user1.commit().unwrap();
        assert_eq!(user1.leaf_secret_key(), secret_key_3);

        let tk2 = user1.root_secret_key();
        assert_ne!(
            tk1,
            user1.root_secret_key(),
            "Sanity check: old tk is different from the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet"
        );
        assert_eq!(user1.leaf_secret_key(), secret_key_3,);

        let tk = change_key_update.apply(&mut user0).unwrap();
        user0.commit().unwrap();
        assert_eq!(user0.root(), user1.root());
        assert_eq!(user0.root_secret_key(), user1.root_secret_key());
        assert_eq!(
            user0.root().right().unwrap().public_key(),
            user1.leaf_public_key(),
        );

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_ne!(
            tk2, tk1,
            "Sanity check: old tk is different from the new one."
        );
    }

    /// Creator, after computing the art with several users, removes the target_user. The
    /// remaining users updates their art, and one of them, also removes target_user (instead
    /// or changing, he merges two updates). Removed user fails to update his art.
    #[test]
    fn test_removal_of_the_same_user() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        let mut user2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

        let mut user3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

        assert!(user0.eq(&user1), "New user received the same art");
        assert!(user0.eq(&user2), "New user received the same art");
        assert!(user0.eq(&user3), "New user received the same art");

        let tk0 = user0.root_secret_key();
        let tk1 = user1.root_secret_key();
        let tk2 = user2.root_secret_key();
        let tk3 = user2.root_secret_key();

        let blanking_secret_key_1 = Fr::rand(&mut rng);
        let blanking_secret_key_2 = Fr::rand(&mut rng);

        // User0 removes second user node from the art.
        let (tk, remove_member_change1) = user0
            .remove_member(&user2.node_index(), blanking_secret_key_1)
            .unwrap();

        remove_member_change1.apply(&mut user0).unwrap();
        user0.commit().unwrap();

        let tk_r1 = user0.root_secret_key();
        assert_ne!(
            tk1, tk_r1,
            "Sanity check: old tk is different from the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet."
        );
        assert_ne!(
            user0, user2,
            "Both users have different view on the state of the art, as they are not synced yet."
        );
        assert_eq!(
            user0
                .public_art()
                .node(&remove_member_change1.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1)
                .into_affine(),
            "The node was removed correctly."
        );

        // Sync other users art
        remove_member_change1.apply(&mut user1).unwrap();
        user1.commit().unwrap();
        remove_member_change1.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        let err = remove_member_change1.apply(&mut user2).err();
        assert!(
            matches!(err, Some(ArtError::InapplicableBlanking)),
            "Must fail to perform art update using blank leaf, but got {:?}.",
            err
        );

        assert_eq!(
            user0,
            user1,
            "Both users have the same view on the state of the art, but have: user0:\n{},\nuser1:\n{}",
            user0.root(),
            user1.root(),
        );
        assert_eq!(
            user0, user3,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .public_art()
                .node(&remove_member_change1.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1)
                .into_affine(),
            "The node was removed correctly."
        );

        // User1 removes second user node from the art.
        let (tk, remove_member_change2) = user1
            .remove_member(&user2.node_index(), blanking_secret_key_2)
            .unwrap();
        user1.apply(&remove_member_change2).unwrap();
        user1.commit().unwrap();

        let tk_r2 = user1.root_secret_key();
        assert_eq!(
            user1
                .public_art()
                .node(&remove_member_change2.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1 + blanking_secret_key_2)
                .into_affine(),
            "The node was removed correctly."
        );
        assert_eq!(
            user1.root().public_key(),
            CortadoAffine::generator().mul(tk_r2).into_affine(),
            "The node was removed correctly."
        );
        assert_ne!(
            tk_r1, tk_r2,
            "Sanity check: old tk is different from the new one."
        );
        assert_eq!(
            tk_r2,
            user1.root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet."
        );
        assert_ne!(
            user1, user2,
            "Both users have different view on the state of the art, as they are not synced yet."
        );

        // Sync other users art
        remove_member_change2.apply(&mut user0).unwrap();
        user0.commit().unwrap();
        remove_member_change2.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        assert_eq!(
            user0.root_secret_key(),
            user1.root_secret_key(),
            "Both users have the same view on the state of the art"
        );

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user0, user3,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .public_art()
                .node(&remove_member_change1.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1 + blanking_secret_key_2)
                .into_affine(),
            "The node was removed correctly."
        );
    }

    #[test]
    fn test_art_key_update() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let main_user_id = 0;
        let test_user_id = 12;
        let secrets = (0..TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.public_art.clone();

        let mut users_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            users_arts.push(PrivateArt::new(public_art.clone(), secrets[i]).unwrap());
        }

        let root_key = private_art.root_secret_key();
        for i in 0..TEST_GROUP_SIZE {
            // Assert creator and users computed the same tree key.
            assert_eq!(users_arts[i].root_secret_key(), root_key);
        }

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = Fr::rand(&mut rng);
        let (tk, change) = users_arts[main_user_id].update_key(main_new_key).unwrap();
        let changes = PrivateBranchChange(main_new_key, change);

        for i in 0..TEST_GROUP_SIZE {
            assert_eq!(users_arts[i].root(), public_art.root());
            changes.apply(&mut users_arts[i]).unwrap();
            users_arts[i].commit().unwrap();
            assert_eq!(
                users_arts[i].root(),
                users_arts[0].root(),
                "Art trees of user {i} and user 0 are different. users_arts[i]:\n{},\nwhen user0:\n{}",
                users_arts[i].root(),
                users_arts[0].root()
            );
            assert_eq!(
                users_arts[i].root_secret_key(),
                users_arts[0].root_secret_key()
            );
            assert_eq!(
                users_arts[i].root_secret_key(),
                tk,
                "users_arts[i]:\n{},\nwhen user0:\n{}",
                users_arts[i].root(),
                users_arts[0].root()
            );
        }

        assert_ne!(users_arts[main_user_id].leaf_secret_key(), main_old_key);

        let mut pub_keys = Vec::new();
        let mut parent = users_arts[main_user_id].root();
        for direction in &users_arts[main_user_id].node_index().get_path().unwrap() {
            pub_keys.push(parent.child(*direction).unwrap().public_key());
            parent = parent.child(*direction).unwrap();
        }
        pub_keys.reverse();

        for (secret_key, corr_pk) in users_arts[main_user_id]
            .secrets
            .commited_secrets()
            .iter()
            .zip(pub_keys.iter())
        {
            assert_eq!(
                CortadoAffine::generator().mul(secret_key).into_affine(),
                *corr_pk,
                "Multiplication done correctly."
            );
        }

        changes.apply(&mut users_arts[test_user_id]).unwrap();
        users_arts[test_user_id].commit().unwrap();

        let new_key = users_arts[main_user_id].root_secret_key();
        assert_eq!(
            users_arts[test_user_id].root(),
            users_arts[main_user_id].root()
        );
        assert_eq!(
            users_arts[test_user_id].root_secret_key(),
            users_arts[main_user_id].root_secret_key()
        );
        assert_eq!(users_arts[test_user_id].root_secret_key(), new_key);

        let (tk, change) = users_arts[main_user_id].update_key(main_old_key).unwrap();
        let changes = PrivateBranchChange(main_old_key, change);

        for i in 0..TEST_GROUP_SIZE {
            changes.apply(&mut users_arts[i]).unwrap();
            users_arts[i].commit().unwrap();
            assert_eq!(users_arts[i].root_secret_key(), tk);
        }

        let recomputed_old_key = users_arts[main_user_id].root_secret_key();
        assert_eq!(tk, recomputed_old_key);
        assert_eq!(root_key, recomputed_old_key);

        for i in 0..TEST_GROUP_SIZE as usize {
            changes.apply(&mut users_arts[i]).unwrap();
            users_arts[i].commit().unwrap();
            assert_eq!(users_arts[i].root_secret_key(), recomputed_old_key);
        }
    }

    /// Main user creates art with four users, then first, second, and third users updates their
    /// arts. The forth user, applies changes, but swaps first two.
    #[test]
    fn test_wrong_changes_commit_ordering() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        assert_ne!(secret_key_1, secret_key_2);
        assert_ne!(secret_key_2, secret_key_3);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        let mut user2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

        let mut user3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk0, key_update_change0) = user0.update_key(new_sk0).unwrap();
        user0.apply(&new_sk0).unwrap();
        user0.commit().unwrap();
        let tk_r0 = user0.root_secret_key();

        // User1 updates his art.
        key_update_change0.apply(&mut user1).unwrap();
        user1.commit().unwrap();
        let new_sk1 = Fr::rand(&mut rng);
        let (tk1, key_update_change1) = user1.update_key(new_sk1).unwrap();
        new_sk1.apply(&mut user1).unwrap();
        user1.commit().unwrap();
        let tk_r1 = user1.root_secret_key();
        assert_eq!(
            tk_r1,
            user1.root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User2 updates his art.
        key_update_change0.apply(&mut user2).unwrap();
        user2.commit().unwrap();
        key_update_change1.apply(&mut user2).unwrap();
        user2.commit().unwrap();
        let new_sk2 = Fr::rand(&mut rng);
        let (tk2, key_update_change2) = user2.update_key(new_sk2).unwrap();
        new_sk2.apply(&mut user2).unwrap();
        user2.commit().unwrap();
        let tk_r2 = user2.root_secret_key();
        assert_eq!(
            tk_r2,
            user2.root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Update art for other users.
        key_update_change1.apply(&mut user3).unwrap();
        user3.commit().unwrap();
        key_update_change0.apply(&mut user3).unwrap();
        user3.commit().unwrap();
        key_update_change2.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        assert_ne!(
            user3.root(),
            user2.root(),
            "Wrong order of updates will bring to different public arts."
        );
    }

    /// The same key update, shouldn't affect the art, as it will be overwritten by itself.
    #[test]
    fn test_apply_key_update_changes_twice() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();
        let def_tk = user0.root_secret_key();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk0, key_update_change0) = user0.update_key(new_sk0).unwrap();
        let tk_r0 = user0.root_secret_key();

        // Update art for other users.
        key_update_change0.apply(&mut user1).unwrap();
        key_update_change0.apply(&mut user1).unwrap();

        assert_eq!(
            user0, user1,
            "Applying of the same key update twice, will give no affect."
        );
    }

    #[test]
    fn test_correctness_for_method_from() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

        let user1_2 =
            PrivateArt::restore(public_art.clone(), user1.secrets.commited_secrets()).unwrap();

        assert_eq!(user1, user1_2);

        assert_eq!(user1.secrets, user1_2.secrets);
    }

    #[test]
    fn test_get_node() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let leaf_secrets = (0..TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut user0: PrivateArt<CortadoAffine> = PrivateArt::setup(&leaf_secrets).unwrap();

        let random_public_key = CortadoAffine::rand(&mut rng);
        assert!(user0.root().node_with(random_public_key).is_err());
        assert!(
            user0
                .public_art()
                .root()
                .leaf_with(random_public_key)
                .is_err()
        );

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf = user0.public_art().root().leaf_with(pk).unwrap();
            assert_eq!(leaf.public_key(), pk);
            assert!(leaf.is_leaf());
        }

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf = user0.public_art().root().node_with(pk).unwrap();
            assert_eq!(leaf.public_key(), pk);
        }

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf_path = user0.public_art().root().path_to_leaf_with(pk).unwrap();
            let leaf = user0
                .public_art()
                .node(&NodeIndex::Direction(leaf_path))
                .unwrap();
            assert_eq!(leaf.public_key(), pk);

            assert!(leaf.is_leaf());
        }
    }

    #[test]
    fn test_apply_key_update_to_itself() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk, key_update_change0) = user0.update_key(new_sk0).unwrap();

        // User1 fails to update his art.
        assert!(matches!(
            key_update_change0.apply(&mut user1),
            Err(ArtError::InapplicableKeyUpdate)
        ));
    }

    #[test]
    fn test_art_weights_after_one_add_member() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut tree: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 1..TEST_GROUP_SIZE {
            let _ = tree.add_member(Fr::rand(&mut rng)).unwrap();
        }

        for node in tree.root() {
            if node.is_leaf() {
                if !matches!(node.status(), Some(LeafStatus::Active)) {
                    assert_eq!(node.weight(), 0);
                } else {
                    assert_eq!(node.weight(), 1);
                }
            } else {
                assert_eq!(
                    node.weight(),
                    node.child(Direction::Left).unwrap().weight()
                        + node.child(Direction::Right).unwrap().weight()
                );
            }
        }
    }

    #[test]
    fn test_weights_correctness_for_make_blank() {
        init_tracing();
        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..9).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let mut user0 = PrivateArt::setup(&secrets).unwrap();

        let target_user_path = user0
            .root()
            .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
            .unwrap();
        let target_user_index = NodeIndex::from(target_user_path);

        let (tk, change) = user0
            .remove_member(&target_user_index, Fr::rand(&mut rng))
            .unwrap();
        change.apply(&mut user0).unwrap();
        user0.commit().unwrap();

        assert_eq!(user0.root().weight() + 1, secrets.len());

        for node in user0.root() {
            if node.is_leaf() {
                if !matches!(node.status(), Some(LeafStatus::Active)) {
                    assert_eq!(node.weight(), 0);
                } else {
                    assert_eq!(node.weight(), 1);
                }
            } else {
                assert_eq!(
                    node.weight(),
                    node.child(Direction::Left).unwrap().weight()
                        + node.child(Direction::Right).unwrap().weight()
                );
            }
        }
    }

    #[test]
    fn test_leaf_status_affect_on_make_blank() {
        init_tracing();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let seed = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);
        let secrets = (0..TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

        let sk_1 = Fr::rand(&mut rng);
        let sk_2 = Fr::rand(&mut rng);
        let user_2_path = art
            .public_art()
            .root()
            .path_to_leaf_with(CortadoAffine::generator().mul(&secrets[1]).into_affine())
            .unwrap();
        let user_2_index = NodeIndex::from(user_2_path.clone());

        let mut art1 = art.clone();
        let (_, remove11) = art1.remove_member(&user_2_index, sk_1).unwrap();
        remove11.apply(&mut art1).unwrap();
        art1.commit().unwrap();
        let (_, remove12) = art1.remove_member(&user_2_index, sk_2).unwrap();
        remove12.apply(&mut art1).unwrap();
        art1.commit().unwrap();
        assert_eq!(
            art1.public_art().node(&user_2_index).unwrap().public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art2 = art.clone();
        art2.public_art
            .mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::PendingRemoval)
            .unwrap();
        let (_, remove21) = art2.remove_member(&user_2_index, sk_1).unwrap();
        remove21.apply(&mut art2).unwrap();
        art2.commit().unwrap();
        let (_, remove22) = art2.remove_member(&user_2_index, sk_2).unwrap();
        remove22.apply(&mut art2).unwrap();
        art2.commit().unwrap();

        assert_eq!(
            art2.public_art().node(&user_2_index).unwrap().public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art3 = art.clone();
        art3.public_art
            .mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::Blank)
            .unwrap();
        let (_, remove31) = art3.remove_member(&user_2_index, sk_1).unwrap();
        remove31.apply(&mut art3).unwrap();
        art3.commit().unwrap();
        let (_, remove32) = art3.remove_member(&user_2_index, sk_2).unwrap();
        remove32.apply(&mut art3).unwrap();
        art3.commit().unwrap();
        assert_eq!(
            art3.public_art().node(&user_2_index).unwrap().public_key(),
            CortadoAffine::generator()
                .mul(&(secrets[1] + sk_1 + sk_2))
                .into_affine()
        );
    }
}
