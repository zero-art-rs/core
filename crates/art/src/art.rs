// Asynchronous Ratchet Tree implementation

use crate::art_node::{ARTNode, ARTNodeError, Direction};
use crate::{ARTRootKey, BranchChanges, BranchChangesType, ark_de, ark_se};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use ark_std::{One, UniformRand, Zero};
use curve25519_dalek::Scalar;
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use serde_json;
use std::cmp::min;
use std::{cmp::max, mem};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ARTError {
    #[error("Error in art logic: {0}")]
    NodesLogicError(#[from] ARTNodeError),
    #[error("Error in art logic: {0}")]
    ARTLogicError(String),
    #[error("Given parameters are invalid: {0}")]
    InvalidParameters(String),
    #[error("Serialization failure: {0}")]
    SerialisationError(String),
}

pub enum NodeIndex {
    Index(usize),
    Coordinate(usize, usize),
    Direction(Vec<Direction>),
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct ART<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}

impl<G> ART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    /// Iota function is a function which converts computed public secret to scalar field. It can
    /// be any function. Here, th function takes x coordinate of affine representation of a point.
    /// If the base field of curve defined on extension of a field, we take the first coefficient.
    pub fn iota_function(point: &G) -> Scalar {
        let x = point.x().unwrap();

        Scalar::from_bytes_mod_order((&x.into_bigint().to_bytes_le()[..]).try_into().unwrap())
    }

    fn compute_next_layer_of_tree(
        level_nodes: &mut Vec<ARTNode<G>>,
        level_secrets: &mut Vec<G::ScalarField>,
        generator: &G,
    ) -> (Vec<ARTNode<G>>, Vec<G::ScalarField>) {
        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();

        // iterate until level_nodes is empty, then swap it with the next layer
        while level_nodes.len() > 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = Self::iota_function(
                &left_node
                    .public_key
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            );

            let ark_common_secret =
                G::ScalarField::from_le_bytes_mod_order(&common_secret.to_bytes());

            let node = ARTNode::new_internal_node(
                generator.mul(&ark_common_secret).into_affine(),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
            upper_level_secrets.push(ark_common_secret);
        }

        // if one have an odd number of nodes, the last one will be added to the next level
        if level_nodes.len() == 1 {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret.clone());
        }

        (upper_level_nodes, upper_level_secrets)
    }

    /// fit all the leaves on the same level, so the tree is balanced
    pub fn fit_leaves_in_one_level(
        mut level_nodes: Vec<ARTNode<G>>,
        mut level_secrets: Vec<G::ScalarField>,
        generator: &G,
    ) -> (Vec<ARTNode<G>>, Vec<G::ScalarField>) {
        let mut level_size = 2;
        while level_size < level_nodes.len() {
            level_size = level_size << 1;
        }

        if level_size == level_nodes.len() {
            return (level_nodes, level_secrets);
        }

        let excess = level_size - level_nodes.len();

        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();
        for i in 0..(level_nodes.len() - excess) >> 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = Self::iota_function(
                &left_node
                    .public_key
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            );

            let ark_common_secret =
                G::ScalarField::from_le_bytes_mod_order(&common_secret.to_bytes());

            let node = ARTNode::new_internal_node(
                generator.mul(&ark_common_secret).into_affine(),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
            upper_level_secrets.push(ark_common_secret);
        }

        for i in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret.clone());
        }

        (upper_level_nodes, upper_level_secrets)
    }

    /// Computes a new tree from th set of given secrets. The first secret is a secret key of the
    /// creator.
    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        if secrets.len() == 0 {
            return Err(ARTError::InvalidParameters(
                "Can't create art of size 0".to_string(),
            ));
        }
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            let node = ARTNode::new_leaf(generator.mul(leaf_secret).into_affine());

            level_nodes.push(node);
            level_secrets.push(leaf_secret.clone());
        }

        // fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets, &generator);
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            (level_nodes, level_secrets) =
                ART::compute_next_layer_of_tree(&mut level_nodes, &mut level_secrets, generator);
        }

        let root = level_nodes.remove(0);
        let root_key = ARTRootKey {
            key: level_secrets.remove(0),
            generator: generator.clone(),
        };

        let art = ART {
            root: Box::new(root),
            generator: generator.clone(),
        };

        Ok((art, root_key))
    }

    /// Returns a reference on a root node
    pub fn get_root(&self) -> &Box<ARTNode<G>> {
        &self.root
    }

    /// changes the root node with the given one. Old root node is returned.
    pub fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>> {
        mem::replace(&mut self.root, new_root)
    }

    /// Returns a co-path to the leaf with a given public key.
    pub fn get_co_path_values(&self, user_public_key: &G) -> Result<Vec<G>, ARTError> {
        let (path_nodes, next_node) = self.get_path_to_leaf(user_public_key)?;

        let mut co_path_values = Vec::new();

        for i in (0..path_nodes.len() - 1).rev() {
            let node = path_nodes.get(i).unwrap();
            let direction = next_node.get(i).unwrap();

            match direction {
                Direction::Left => co_path_values.push(node.get_right()?.public_key),
                Direction::Right => co_path_values.push(node.get_left()?.public_key),
                _ => return Err(ARTError::ARTLogicError("Unexpected direction".to_string())),
            }
        }

        Ok(co_path_values)
    }

    /// Searches the tree for a leaf node that matches the given public key, and returns the
    /// path taken to reach it. Search approach used is depth-first search.
    pub fn get_path_to_leaf(
        &self,
        user_val: &G,
    ) -> Result<(Vec<&ARTNode<G>>, Vec<Direction>), ARTError> {
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.public_key.eq(user_val) {
                    next.pop();
                    return Ok((path, next));
                } else {
                    path.pop();
                    next.pop();
                }
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right()?.as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left()?.as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Err(ARTError::ARTLogicError("Can't find a path.".to_string()))
    }

    /// Recomputes art root key using the given leaf secret key.
    pub fn recompute_root_key(
        &self,
        secret_key: G::ScalarField,
    ) -> Result<ARTRootKey<G>, ARTError> {
        let co_path_values = self.get_co_path_values(&self.public_key_of(&secret_key))?;

        let mut ark_secret = secret_key.clone();
        for public_key in co_path_values.iter() {
            let secret = Self::iota_function(&public_key.mul(ark_secret).into_affine());
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
        }

        Ok(ARTRootKey {
            key: ark_secret,
            generator: self.generator.clone(),
        })
    }

    /// Recomputes art root key using the given leaf secret key.
    pub fn recompute_root_key_with_artefacts(
        &self,
        secret_key: G::ScalarField,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError> {
        let co_path_values = self.get_co_path_values(&self.public_key_of(&secret_key))?;

        let mut ark_secret = secret_key.clone();
        let mut secrets: Vec<Scalar> = vec![Scalar::from_bytes_mod_order(
            (&secret_key.clone().into_bigint().to_bytes_le()[..])
                .try_into()
                .unwrap(),
        )];
        for public_key in co_path_values.iter() {
            let secret = Self::iota_function(&public_key.mul(ark_secret).into_affine());
            secrets.push(secret.clone());
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
        }

        Ok((
            ARTRootKey {
                key: ark_secret,
                generator: self.generator.clone(),
            },
            co_path_values,
            secrets,
        ))
    }

    /// Shorthand for computing public key.
    fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.generator.mul(secret).into_affine()
    }

    /// Update all public keys on path from the root to node, corresponding to the given secret
    /// key. Can be used to update art after applied changes.
    pub fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let (_, mut next) = self.get_path_to_leaf(&self.public_key_of(secret_key))?;

        let mut changes = BranchChanges {
            change_type: BranchChangesType::UpdateKeys,
            public_keys: Vec::new(),
            next: next.clone(),
        };

        let mut public_key = self.public_key_of(secret_key);

        let mut ark_level_secret_key = secret_key.clone();
        while !next.is_empty() {
            let next_child = next.pop().unwrap();

            let mut parent = self.root.as_mut();
            for direction in &next {
                parent = parent.get_mut_child(direction)?;
            }

            parent
                .get_mut_child(&next_child)?
                .set_public_key(public_key);

            changes.public_keys.push(public_key);

            let other_child_public_key = parent.get_other_child(&next_child)?.public_key.clone();
            let common_secret = other_child_public_key
                .mul(ark_level_secret_key)
                .into_affine();
            let level_secret_key = Self::iota_function(&common_secret);
            ark_level_secret_key =
                G::ScalarField::from_le_bytes_mod_order(&level_secret_key.to_bytes());
            public_key = self.generator.mul(&ark_level_secret_key).into_affine();
        }

        self.root.set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: ark_level_secret_key,
            generator: self.generator.clone(),
        };

        Ok((key, changes))
    }

    /// Changes old_secret_key secret key of a leaf to the new_secret_key.
    pub fn update_key(
        &mut self,
        old_secret_key: &G::ScalarField,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let (_, next) = self.get_path_to_leaf(&self.public_key_of(old_secret_key))?;
        let new_public_key = self.public_key_of(new_secret_key);

        let user_node = self.get_node_by_path(next)?;
        user_node.set_public_key(new_public_key);

        self.update_art_with_secret_key(&new_secret_key)
    }

    /// Returns random scalar, which is not one or zero.
    pub fn get_random_scalar(&self) -> G::ScalarField {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let mut k = G::ScalarField::zero();
        while k.is_one() || k.is_zero() {
            k = G::ScalarField::rand(&mut rng);
        }

        k
    }

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left-most branch.
    pub fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, ARTError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate.get_left()?;
            let r = candidate.get_right()?;

            match l.weight <= r.weight {
                true => {
                    next.push(Direction::Left);
                    candidate = candidate.get_left()?;
                }
                false => {
                    next.push(Direction::Right);
                    candidate = candidate.get_right()?;
                }
            }
        }

        Ok(next)
    }

    /// Extends a leaf on the end of a given path with the given node. This method don't change
    /// other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc.
    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &Vec<Direction>,
    ) -> Result<(), ARTError> {
        let mut node_for_extension = self.root.as_mut();
        for direction in path {
            node_for_extension.weight += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension.get_mut_child(direction)?;
        }

        // The last node weight is done automatically through the extension methods
        node_for_extension.weight -= 1;
        node_for_extension.extend_or_replace(node)?;

        Ok(())
    }

    /// Extends the leaf on a path with new node. New node contains public key corresponding to a
    /// given secret key. Then it updates necessary public keys on a path to root using new
    /// node temporal secret key. Returns new ARTRootKey and BranchChanges for other users.
    pub fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let path = self.find_path_to_possible_leaf_for_insertion()?;
        let node = ARTNode::new_leaf(self.public_key_of(&secret_key));

        self.append_node_without_changes(node.clone(), &path)?;

        self.update_art_with_secret_key(secret_key)
            .map(|(root_key, mut changes)| {
                changes.change_type = BranchChangesType::AppendNode(node);
                (root_key, changes)
            })
    }

    /// Converts the leaf on a given path to temporal by changing its public key on given temporal
    /// one. This method don't change other art nodes. To update art use update_art_with_secret_key
    /// or update_art_with_changes
    fn make_temporal_without_changes(
        &mut self,
        path: &Vec<Direction>,
        temporal_public_key: &G,
    ) -> Result<(), ARTError> {
        let mut target_node = self.root.as_mut();
        for direction in path {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }
        target_node.make_temporal(temporal_public_key)?;

        Ok(())
    }

    /// Converts the leaf on a given path to temporal by changing its public key on given temporal
    /// one. At the end, updates necessary public keys on a path to root. Returns new ARTRootKey
    /// and BranchChanges for other users.
    pub fn make_node_temporal(
        &mut self,
        public_key: &G,
        temporal_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let new_public_key = self.public_key_of(temporal_secret_key);
        let (_, next) = self.get_path_to_leaf(public_key)?;

        self.make_temporal_without_changes(&next, &new_public_key)?;

        self.update_art_with_secret_key(temporal_secret_key)
            .map(|(root_key, mut changes)| {
                changes.change_type = BranchChangesType::MakeTemporal(
                    public_key.clone(),
                    temporal_secret_key.clone(),
                );
                (root_key, changes)
            })
    }

    /// Updates art public keys using public keys provided in changes. Can be used after
    /// operations on art like append_node, etc.
    pub fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        let mut current_node = self.root.as_mut();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key(changes.public_keys[i].clone());
            current_node = current_node.get_mut_child(changes.next.get(i).unwrap())?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1].clone());

        Ok(())
    }

    /// Uses public keys provided in changes to change public keys of art.
    /// Those public keys are located on a path from root to node, corresponding to user, which
    /// provided changes.
    fn update_art_with_changes_and_path(
        &mut self,
        changes: &BranchChanges<G>,
        path: &Vec<Direction>,
    ) -> Result<(), ARTError> {
        let mut current_node = self.root.as_mut();
        for (next, public_key) in path
            .iter()
            .zip(changes.public_keys[..changes.public_keys.len() - 1].iter())
        {
            current_node.set_public_key(public_key.clone());
            current_node = current_node.get_mut_child(next)?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1].clone());

        Ok(())
    }

    /// Returns mutable node by the given path to it
    fn get_node_by_path(&mut self, next: Vec<Direction>) -> Result<&mut ARTNode<G>, ARTError> {
        let mut target_node = self.root.as_mut();
        for direction in &next {
            target_node = target_node.get_mut_child(direction)?;
        }

        Ok(target_node)
    }

    /// Returns mutable node by the given coordinate of a node. For example, the root is (l:0, p:0),
    /// while its childrens are (l: 1, p: 0) and l: 1, p: 1).
    pub fn get_node_by_coordinate(
        &mut self,
        level: usize,
        position: usize,
    ) -> Result<&mut ARTNode<G>, ARTError> {
        if position >= (2 << level) {
            return Err(ARTError::InvalidParameters(
                "position out of bounds".to_string(),
            ));
        }

        let mut target_node = self.root.as_mut();
        let mut l = level;
        let mut p = position;
        while l != 0 {
            // max number of leaves on level l in a subtree divided by 2
            let relative_center_index = 1 << (l - 1);
            if p < relative_center_index {
                // node is on the left form target_node
                target_node = target_node.get_mut_left()?;
            } else {
                // node is on the right from target_node
                target_node = target_node.get_mut_right()?;
                p = p - relative_center_index;
            }

            l -= 1;
        }

        Ok(target_node)
    }

    /// Returns mutable node by the given index of a node. For example, root have index 0, its
    /// children are 1 and 2.
    pub fn get_node_by_index(&mut self, index: usize) -> Result<&mut ARTNode<G>, ARTError> {
        if index == 0 {
            return Err(ARTError::InvalidParameters(
                "The enumeration of nodes starts with 1".to_string(),
            ));
        }

        let mut i = index;

        let mut path = Vec::new();
        while i > 1 {
            if (i & 1) == 0 {
                path.push(Direction::Left);
            } else {
                path.push(Direction::Right);
            }

            i = i >> 1;
        }

        let mut target_node = self.root.as_mut();
        for direction in path.iter().rev() {
            target_node = target_node.get_mut_child(direction)?;
        }

        Ok(target_node)
    }

    /// Returns mutable node by the given NodeIndex
    fn get_node(&mut self, index: NodeIndex) -> Result<&mut ARTNode<G>, ARTError> {
        match index {
            NodeIndex::Index(index) => self.get_node_by_index(index),
            NodeIndex::Coordinate(level, position) => self.get_node_by_coordinate(level, position),
            NodeIndex::Direction(path) => self.get_node_by_path(path),
        }
    }

    /// This check says if the node can be immediately removed from a tree. Those cases are
    /// specific, so in general don't remove nodes and make them temporal instead
    pub fn can_remove(&mut self, lambda: &G::ScalarField, public_key: &G) -> bool {
        let users_public_key = self.public_key_of(lambda);

        if users_public_key.eq(public_key) {
            return false;
        }

        let (_, path_to_other) = self.get_path_to_leaf(public_key).unwrap();
        let (_, path_to_self) = self.get_path_to_leaf(&users_public_key).unwrap();

        if path_to_other.len().abs_diff(path_to_self.len()) > 1 {
            return false;
        }

        for i in 0..(max(path_to_self.len(), path_to_other.len()) - 2) {
            if path_to_self[i] != path_to_other[i] {
                return false;
            }
        }

        true
    }

    /// Remove the last node in the given path if can
    fn remove_node(&mut self, path: &Vec<Direction>) -> Result<(), ARTError> {
        let mut target_node = self.root.as_mut();
        for direction in &path[..path.len() - 1] {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }

        target_node.shrink_to_other(path[path.len() - 1])?;

        Ok(())
    }

    /// Remove the last node in the given path if can and update public keys on a path from root to
    /// leaf
    fn remove_node_and_update_tree(
        &mut self,
        lambda: &G::ScalarField,
        public_key: &G,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        if !self.can_remove(lambda, public_key) {
            return Err(ARTError::InvalidParameters(
                "Can't remove a node, because the given node isn't close enough".to_string(),
            ));
        }

        let (_, path) = self.get_path_to_leaf(public_key)?;
        self.remove_node(&path)?;

        match self.update_art_with_secret_key(lambda) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::RemoveNode(public_key.clone());

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    fn min_max_leaf_height(&self) -> Result<(usize, usize), ARTError> {
        let mut min_height = usize::MAX;
        let mut max_height = 0;
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                min_height = min(min_height, path.len());
                max_height = max(max_height, path.len());

                path.pop();
                next.pop();
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right()?.as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left()?.as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Ok((min_height, max_height))
    }

    pub fn get_disbalance(&self) -> Result<usize, ARTError> {
        let (min_height, max_height) = self.min_max_leaf_height()?;

        Ok(max_height - min_height)
    }

    /// Updates art with given changes.
    pub fn update_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKeys => self.update_art_with_changes(changes),
            BranchChangesType::AppendNode(node) => {
                let path = self.find_path_to_possible_leaf_for_insertion()?;
                self.append_node_without_changes(node.clone(), &path)?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::MakeTemporal(public_key, temporal_lambda) => {
                let (_, path) = self.get_path_to_leaf(public_key)?;
                self.make_temporal_without_changes(&path, &self.public_key_of(temporal_lambda))?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::RemoveNode(public_key) => {
                let (_, path) = self.get_path_to_leaf(public_key)?;
                self.remove_node(&path)?;
                self.update_art_with_changes(changes)
            }
        }
    }

    pub fn serialise_with_serde_json(&self) -> Result<String, ARTError> {
        match serde_json::to_string(&self) {
            Ok(json) => Ok(json),
            Err(e) => Err(ARTError::SerialisationError(format!(
                "Failed to serialise: {:?}",
                e
            ))),
        }
    }

    pub fn serialise_with_postcard(&self) -> Result<Vec<u8>, ARTError> {
        match to_allocvec(self) {
            Ok(output) => Ok(output),
            Err(e) => Err(ARTError::SerialisationError(format!(
                "Failed to serialise: {:?}",
                e
            ))),
        }
    }

    pub fn to_string(&self) -> Result<String, ARTError> {
        self.serialise_with_serde_json()
    }

    pub fn deserialize_with_postcard(bytes: &Vec<u8>) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(|e| ARTError::SerialisationError(e.to_string()))
    }

    pub fn from_string(canonical_json: &String) -> Result<Self, ARTError> {
        serde_json::from_str(canonical_json)
            .map_err(|e| ARTError::SerialisationError(format!("Failed to deserialize: {:?}", e)))
    }
}

impl<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> PartialEq for ART<G> {
    fn eq(&self, other: &Self) -> bool {
        !(self.root != other.root || self.generator != other.generator)
    }
}
