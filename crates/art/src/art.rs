// Asynchronous Ratchet Tree implementation

use crate::art_node::{ARTNode, Direction};
use crate::helper_tools::{ark_de, ark_se};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use ark_std::{One, UniformRand, Zero};
use serde::{Deserialize, Serialize};
use serde_json;
use std::{cmp::max, mem};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub enum BranchChangesType<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> {
    MakeTemporal(
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G,
        #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")] G::ScalarField,
    ),
    AppendNode(ARTNode<G>),
    UpdateKeys,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    RemoveNode(G),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct BranchChanges<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> {
    pub change_type: BranchChangesType<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_keys: Vec<G>,
    pub next: Vec<Direction>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(bound = "")]
pub struct ARTRootKey<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub key: G::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct ART<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> {
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}

impl<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> ART<G> {
    /// Iota function is a function which converts computed public secret to scalar field. It can
    /// be any function. Here, th function takes x coordinate of affine representation of a point.
    /// If the base field of curve defined on extension of a field, we take the first coefficient.
    pub fn iota_function(point: &G) -> G::ScalarField {
        // Convert into affine representation, so the result will always be the same
        let x = point.into_affine().x().unwrap();
        let base_field_x = x.to_base_prime_field_elements().next().unwrap();
        let x_bigint = base_field_x.into_bigint().to_bytes_le();
        G::ScalarField::from_le_bytes_mod_order(x_bigint.as_slice())
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

            let common_secret =
                Self::iota_function(&left_node.public_key.mul(level_secrets.remove(0)));

            let node = ARTNode::new_internal_node(
                generator.mul(&common_secret),
                Box::new(left_node),
                Box::new(right_node),
            );

            upper_level_nodes.push(node);
            upper_level_secrets.push(common_secret);
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

    /// Computes a new tree from th set of given secrets. The first secret is a secret key of the
    /// creator.
    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> (Self, ARTRootKey<G>) {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            let node = ARTNode::new_leaf(generator.mul(leaf_secret));

            level_nodes.push(node);
            level_secrets.push(leaf_secret.clone());
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

        (art, root_key)
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
    pub fn get_co_path_values(&self, user_public_key: &G) -> Result<Vec<G>, String> {
        let (path_nodes, next_node) = self.get_path_to_leaf(user_public_key)?;

        let mut co_path_values = Vec::new();

        for i in (0..path_nodes.len() - 1).rev() {
            let node = path_nodes.get(i).unwrap();
            let direction = next_node.get(i).unwrap();

            match direction {
                Direction::Left => co_path_values.push(node.get_right().public_key),
                Direction::Right => co_path_values.push(node.get_left().public_key),
                _ => return Err("Unexpected direction".into()),
            }
        }

        Ok(co_path_values)
    }

    /// Searches the tree for a leaf node that matches the given public key, and returns the
    /// path taken to reach it. Search approach used is depth-first search.
    pub fn get_path_to_leaf(
        &self,
        user_val: &G,
    ) -> Result<(Vec<&ARTNode<G>>, Vec<Direction>), String> {
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
                        path.push(last_node.get_right().as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left().as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Err("Can't find a path.".to_string())
    }

    /// Recomputes art root key using the given leaf secret key.
    pub fn recompute_root_key(&self, secret_key: G::ScalarField) -> Result<ARTRootKey<G>, String> {
        let co_path_values = self.get_co_path_values(&self.public_key_of(&secret_key))?;

        let mut secret = secret_key.clone();
        for public_key in co_path_values.iter() {
            secret = Self::iota_function(&public_key.mul(secret));
        }

        Ok(ARTRootKey {
            key: secret,
            generator: self.generator.clone(),
        })
    }

    /// Shorthand for computing public key.
    fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.generator.mul(secret)
    }

    /// Update all public keys on path from the root to node, corresponding to the given secret
    /// key. Can be used to update art after applied changes.
    pub fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), String> {
        let (_, mut next) = self.get_path_to_leaf(&self.public_key_of(secret_key))?;

        let mut changes = BranchChanges {
            change_type: BranchChangesType::UpdateKeys,
            public_keys: Vec::new(),
            next: next.clone(),
        };

        let mut public_key = self.public_key_of(secret_key);

        let mut level_secret_key = secret_key.clone();
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
            let common_secret = other_child_public_key.mul(level_secret_key);
            level_secret_key = Self::iota_function(&common_secret);
            public_key = self.generator.mul(&level_secret_key);
        }

        self.root.set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: level_secret_key,
            generator: self.generator.clone(),
        };

        Ok((key, changes))
    }

    /// Changes old_secret_key secret key of a leaf to the new_secret_key.
    pub fn update_key(
        &mut self,
        old_secret_key: &G::ScalarField,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), String> {
        let (_, next) = self.get_path_to_leaf(&self.public_key_of(old_secret_key))?;
        let new_public_key = self.public_key_of(new_secret_key);

        let user_node = self.get_to_node(next)?;
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
    pub fn find_path_to_possible_leaf_for_insertion(&self) -> Vec<Direction> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate.get_left();
            let r = candidate.get_right();

            match l.weight <= r.weight {
                true => {
                    next.push(Direction::Left);
                    candidate = candidate.get_left();
                }
                false => {
                    next.push(Direction::Right);
                    candidate = candidate.get_right();
                }
            }
        }

        next
    }

    /// Extends a leaf on the end of a given path with the given node. This method don't change
    /// other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc.
    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &Vec<Direction>,
    ) -> Result<(), String> {
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
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), String> {
        let path = self.find_path_to_possible_leaf_for_insertion();
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
    ) -> Result<(), String> {
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
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), String> {
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
    pub fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), String> {
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
    ) -> Result<(), String> {
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
    fn get_to_node(&mut self, next: Vec<Direction>) -> Result<&mut ARTNode<G>, String> {
        let mut target_node = self.root.as_mut();
        for direction in &next {
            target_node = target_node.get_mut_child(direction)?;
        }

        Ok(target_node)
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
    fn remove_node(&mut self, path: &Vec<Direction>) -> Result<(), String> {
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
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), String> {
        if !self.can_remove(lambda, public_key) {
            return Err("Can't remove a node, because the given node isn't close enough".into());
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

    /// Updates art with given changes.
    pub fn update_art(&mut self, changes: &BranchChanges<G>) -> Result<(), String> {
        match &changes.change_type {
            BranchChangesType::UpdateKeys => self.update_art_with_changes(changes),
            BranchChangesType::AppendNode(node) => {
                let path = self.find_path_to_possible_leaf_for_insertion();
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

    pub fn to_string(&self) -> Result<String, String> {
        match serde_json::to_string(&self) {
            Ok(json) => Ok(json),
            Err(e) => Err(format!("Failed to serialise: {:?}", e)),
        }
    }

    pub fn from_string(canonical_json: &String) -> Result<Self, String> {
        let tree: Self = match serde_json::from_str(canonical_json) {
            Ok(tree) => tree,
            Err(e) => return Err(format!("Failed to deserialize: {:?}", e)),
        };

        Ok(tree)
    }
}

impl<G: CurveGroup + CanonicalSerialize + CanonicalDeserialize> PartialEq for ART<G> {
    fn eq(&self, other: &Self) -> bool {
        !(self.root != other.root || self.generator.into_affine() != other.generator.into_affine())
    }
}
