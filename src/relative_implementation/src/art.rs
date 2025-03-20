// Asynchronous Ratchet Tree implementation

use std::fmt::format;
use crate::ibbe_del7::{MasterSecretKey, PublicKey, SecretKey, UserIdentity};
use crate::tools;
use ark_bn254::{
    Bn254, Config, Fq, Fq12Config, G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField,
    fr::FrConfig,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{Field, Fp12, Fp12Config, Fp256, MontBackend, PrimeField, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::iterable::Iterable;
use ark_std::{One, UniformRand, Zero};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use serde_json;
use std::mem;
use std::ops::{Add, DerefMut, Mul};
use ark_ec::{CurveGroup, PrimeGroup};
// use ark_ff::BigInteger;
use ark_ff::BigInt;

// For serialisation
fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}

// For deserialization
fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: Vec<u8> = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Direction {
    NoDirection,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy)]
pub struct ARTCiphertext {
    pub c: G1,
}

#[derive(Debug, Clone)]
pub enum BranchChangesType {
    MakeTemporal(G1, Fp12<Fq12Config>),
    AppendNode(ARTNode),
    UpdateKeys,
    RemoveNode(G1),
}

#[derive(Debug, Clone)]
pub struct BranchChanges {
    pub change_type: BranchChangesType,
    pub public_keys: Vec<G1>,
    pub next: Vec<Direction>,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
pub struct ARTRootKey {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub key: ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub lambda: Option<Fp12<Fq12Config>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G1,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ARTNode {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    public_key: G1,
    l: Option<Box<ARTNode>>,
    r: Option<Box<ARTNode>>,
    is_temporal: bool,
}

impl ARTNode {
    pub fn new(public_key: G1, l: Option<Box<ARTNode>>, r: Option<Box<ARTNode>>) -> ARTNode {
        ARTNode {
            public_key,
            l,
            r,
            is_temporal: false,
        }
    }

    pub fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    pub fn get_left(&self) -> &Box<ARTNode> {
        match &self.l {
            Some(l) => l,
            None => panic!("Leaf doesn't have a left child."),
        }
    }

    pub fn make_temporal(&mut self, temporal_public_key: G1) {
        if self.is_leaf() {
            self.set_public_key(temporal_public_key);
            self.is_temporal = true;
        }
    }

    pub fn get_mut_left(&mut self) -> &mut Box<ARTNode> {
        match &mut self.l {
            Some(l) => l,
            None => panic!("Leaf doesn't have a left child."),
        }
    }

    pub fn get_right(&self) -> &Box<ARTNode> {
        match &self.r {
            Some(r) => r,
            None => panic!("Leaf doesn't have a right child."),
        }
    }

    pub fn get_mut_right(&mut self) -> &mut Box<ARTNode> {
        match &mut self.r {
            Some(r) => r,
            None => panic!("Leaf doesn't have a right child."),
        }
    }

    pub fn set_left(&mut self, other: ARTNode) {
        self.l = Some(Box::new(other));
    }

    pub fn set_right(&mut self, other: ARTNode) {
        self.r = Some(Box::new(other));
    }

    pub fn get_public_key(&self) -> G1 {
        self.public_key.clone()
    }

    pub fn set_public_key(&mut self, public_key: G1) {
        self.public_key = public_key;
    }

    pub fn have_child(&self, child: &Direction) -> bool {
        match child {
            Direction::Left => self.l.is_some(),
            Direction::Right => self.r.is_some(),
            _ => false,
        }
    }

    pub fn get_child(&self, child: &Direction) -> Result<&Box<ARTNode>, String> {
        match child {
            Direction::Left => Ok(self.get_left()),
            Direction::Right => Ok(self.get_right()),
            Direction::NoDirection => Err("Unexpected direction".into()),
        }
    }

    pub fn get_mut_child(&mut self, child: &Direction) -> Result<&mut Box<ARTNode>, String> {
        match child {
            Direction::Left => Ok(self.l.as_mut().unwrap()),
            Direction::Right => Ok(self.r.as_mut().unwrap()),
            Direction::NoDirection => Err("Unexpected direction".into()),
        }
    }

    pub fn get_other_child(&self, child: &Direction) -> Result<&Box<ARTNode>, String> {
        match child {
            Direction::Left => Ok(self.get_right()),
            Direction::Right => Ok(self.get_left()),
            Direction::NoDirection => Err("Unexpected direction".into()),
        }
    }

    pub fn get_mut_other_child(&mut self, child: &Direction) -> Result<&mut Box<ARTNode>, String> {
        match child {
            Direction::Left => Ok(self.r.as_mut().unwrap()),
            Direction::Right => Ok(self.l.as_mut().unwrap()),
            Direction::NoDirection => Err("Unexpected direction".into()),
        }
    }

    // Move current node down to left child, and append other node to right
    pub fn extend(&mut self, other: ARTNode) {
        let new_self = ARTNode {
            public_key: self.public_key.clone(),
            l: self.l.take(),
            r: self.r.take(),
            is_temporal: false,
        };

        self.l = Some(Box::new(new_self));
        self.r = Some(Box::new(other));
    }

    pub fn replace_with(&mut self, other: ARTNode) {
        self.set_public_key(other.get_public_key());
        self.l = other.l;
        self.r = other.r;
        self.is_temporal = other.is_temporal;
    }

    pub fn extend_or_replace(&mut self, other: ARTNode) {
        match self.is_temporal {
            true => self.replace_with(other),
            false => self.extend(other),
        }
    }

    // Change current node with child. Other child is removed
    pub fn shrink_to(&mut self, child: Direction) -> Result<Option<Box<ARTNode>>, String> {
        let (mut new_self, mut other_child) = match child {
            Direction::Left => (self.l.take(), self.r.take()),
            Direction::Right => (self.r.take(), self.l.take()),
            _ => return Err("Unexpected direction".into()),
        };

        let mut new_self = new_self.unwrap();

        self.public_key = new_self.public_key.clone();
        self.l = new_self.l.take();
        self.r = new_self.r.take();

        Ok(other_child)
    }

    pub fn shrink_to_other(
        &mut self,
        for_removal: Direction,
    ) -> Result<Option<Box<ARTNode>>, String> {
        match for_removal {
            Direction::Left => self.shrink_to(Direction::Right),
            Direction::Right => self.shrink_to(Direction::Left),
            _ => return Err("Unexpected direction".into()),
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ART {
    root: Box<ARTNode>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    generator: G1,
    size: usize,
}

impl ART {
    pub fn iota_function(point: &G1) -> ScalarField {
        ScalarField::from(point.into_affine().x.into_bigint())
    }

    pub fn convert_lambda_to_scalar_field(element: &Fp12<Fq12Config>) -> ScalarField {
        tools::sha512_from_byte_vec_to_scalar_field(&element.to_string().into_bytes())
    }

    fn compute_next_layer_of_tree(
        level_nodes: &mut Vec<ARTNode>,
        level_secrets: &mut Vec<ScalarField>,
        generator: &G1,
    ) -> (Vec<ARTNode>, Vec<ScalarField>) {
        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();

        // iterate until level_nodes is empty, then swap it with the next layer
        while level_nodes.len() > 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = left_node.public_key.mul(level_secrets.remove(0));
            let secret_hash = Self::iota_function(&common_secret);

            let node = ARTNode::new(
                generator.mul(&secret_hash),
                Some(Box::new(left_node)),
                Some(Box::new(right_node)),
            );

            upper_level_nodes.push(node);
            upper_level_secrets.push(secret_hash);
        }

        if level_nodes.len() == 1 {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret.clone());
        }

        (upper_level_nodes, upper_level_secrets)
    }

    pub fn new_art_from_secrets(
        secrets: &Vec<Fp12<Fq12Config>>,
        generator: &G1,
    ) -> (Self, ARTRootKey) {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            // compute as hash to resolve type conflict
            let secret = Self::convert_lambda_to_scalar_field(leaf_secret);

            let node = ARTNode::new(generator.mul(secret), None, None);

            level_nodes.push(node);
            level_secrets.push(secret);
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            (level_nodes, level_secrets) =
                ART::compute_next_layer_of_tree(&mut level_nodes, &mut level_secrets, generator);
        }

        let root = level_nodes.remove(0);
        let root_key = ARTRootKey {
            key: level_secrets.remove(0),
            lambda: None,
            generator: generator.clone(),
        };

        let art = ART {
            root: Box::new(root),
            generator: generator.clone(),
            size: secrets.len(),
        };

        (art, root_key)
    }

    pub fn get_root(&self) -> &Box<ARTNode> {
        &self.root
    }

    pub fn replace_root(&mut self, new_root: Box<ARTNode>) -> Box<ARTNode> {
        mem::replace(&mut self.root, new_root)
    }

    pub fn get_co_path_values(&self, user_public_key: G1) -> Result<Vec<G1>, String> {
        let (path_nodes, next_node) = self.get_path(user_public_key)?;

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

    pub fn get_path(&self, user_val: G1) -> Result<(Vec<&ARTNode>, Vec<Direction>), String> {
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.public_key.eq(&user_val) {
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

    pub fn recompute_root_key(&self, lambda: Fp12<Fq12Config>) -> ARTRootKey {
        let mut secret_key = Self::convert_lambda_to_scalar_field(&lambda);

        let user_public_key = self.generator.mul(secret_key);
        let co_path_values = self.get_co_path_values(user_public_key).unwrap();

        //initialize with zero, to resolve compile error
        let mut upper_level_public_key = G1::zero();

        for public_keys in co_path_values.iter() {
            secret_key = Self::iota_function(&public_keys.mul(secret_key));
            upper_level_public_key = self.generator.mul(secret_key);
        }

        ARTRootKey {
            key: secret_key,
            lambda: Some(lambda),
            generator: self.generator.clone(),
        }
    }

    pub fn public_key_from_lambda(&self, lambda: Fp12<Fq12Config>) -> G1 {
        let secret_key = Self::convert_lambda_to_scalar_field(&lambda);
        self.generator.mul(secret_key)
    }

    pub fn height(&self) -> usize {
        match self.size.is_power_of_two() {
            true => self.size.ilog2() as usize,
            false => (self.size.ilog2() + 1) as usize,
        }
    }

    pub fn update_branch_public_keys(
        &mut self,
        lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        let (_, mut next) = self.get_path(self.public_key_from_lambda(lambda))?;

        let mut changes = BranchChanges {
            change_type: BranchChangesType::UpdateKeys,
            public_keys: Vec::new(),
            next: next.clone(),
        };

        let mut secret_key = Self::convert_lambda_to_scalar_field(&lambda);
        let mut public_key = self.generator.mul(secret_key);

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
            let secret = other_child_public_key.mul(secret_key);
            secret_key = Self::iota_function(&secret);
            public_key = self.generator.mul(&secret_key);
        }

        self.root.set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: secret_key,
            lambda: Some(lambda),
            generator: self.generator.clone(),
        };

        Ok((key, changes))
    }

    pub fn change_lambda(
        &mut self,
        old_lambda: Fp12<Fq12Config>,
        new_lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        let (_, mut next) = self.get_path(self.public_key_from_lambda(old_lambda))?;
        let new_public_key = self.public_key_from_lambda(new_lambda);

        let mut user_node = self.get_to_node(next)?;
        user_node.set_public_key(new_public_key);

        self.update_branch_public_keys(new_lambda)
    }

    pub fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, String> {
        let root = self.get_root();
        let height = self.height();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                // there is <=, because next contains additional NoDirection
                if next.len() <= height || last_node.is_temporal {
                    return Ok(next);
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

        Err("Can't find a place for insertion.".into())
    }

    pub fn is_full_binary_tree(&self) -> bool {
        self.size.is_power_of_two()
    }

    fn find_place_and_append_node(&mut self, node: ARTNode) -> Result<(), String> {
        match self.is_full_binary_tree() {
            true => {
                self.root.extend(node);
            }
            false => {
                let mut next = self.find_path_to_possible_leaf_for_insertion()?;

                let mut node_for_extension = self.root.as_mut();
                for direction in &next {
                    if node_for_extension.have_child(direction) {
                        node_for_extension = node_for_extension.get_mut_child(direction)?;
                    } else {
                        break;
                    }
                }

                node_for_extension.extend_or_replace(node);
            }
        };

        self.size += 1;

        Ok(())
    }

    pub fn append_node_by_lambda(
        &mut self,
        lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        let secret_key = Self::convert_lambda_to_scalar_field(&lambda);
        let new_public_key = self.generator.mul(secret_key);

        let new_node = ARTNode::new(new_public_key, None, None);

        self.find_place_and_append_node(new_node.clone())?;

        match self.update_branch_public_keys(lambda) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::AppendNode(new_node);

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    pub fn change_node_to_temporal(
        &mut self,
        public_key: G1,
        temporal_lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        let temporal_secret_key = Self::convert_lambda_to_scalar_field(&temporal_lambda);
        let new_public_key = self.generator.mul(temporal_secret_key);

        let (_, mut next) = self.get_path(public_key)?;

        self.get_to_node(next)?.make_temporal(new_public_key);

        match self.update_branch_public_keys(temporal_lambda) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::MakeTemporal(public_key, temporal_lambda);

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    pub fn update_branch_public_keys_using_changes(
        &mut self,
        changes: &BranchChanges,
    ) -> Result<(), String> {
        let mut current_node = self.root.as_mut();
        for i in (0..changes.public_keys.len() - 1) {
            current_node.set_public_key(changes.public_keys[i].clone());
            current_node = current_node.get_mut_child(changes.next.get(i).unwrap())?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1].clone());

        Ok(())
    }

    pub fn get_to_node(&mut self, next: Vec<Direction>) -> Result<&mut ARTNode, String> {
        let mut target_node = self.root.as_mut();
        for direction in &next {
            target_node = target_node.get_mut_child(direction)?;
        }

        Ok(target_node)
    }

    pub fn can_remove(&mut self, lambda: Fp12<Fq12Config>, public_key: G1) -> bool {
        let users_public_key = self.public_key_from_lambda(lambda);

        if users_public_key == public_key {
            return false;
        }

        let (_, mut path_to_other) = self.get_path(public_key).unwrap();
        let (_, mut path_to_self) = self.get_path(users_public_key).unwrap();

        if path_to_other.len() != path_to_self.len() {
            return false;
        }

        for i in 0..(path_to_self.len() - 2) {
            if path_to_self[i] != path_to_self[i] {}
        }

        true
    }
    pub fn remove_node_from_tree(&mut self, neighbour_public_key: G1) -> Result<(), String> {
        let (_, mut next) = self.get_path(neighbour_public_key)?;
        let for_deletion = next.pop().unwrap();
        let parent = self.get_to_node(next)?;

        parent.shrink_to_other(for_deletion)?;
        self.size -= 1;

        Ok(())
    }

    pub fn remove_node(
        &mut self,
        lambda: Fp12<Fq12Config>,
        public_key: G1,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        if !self.can_remove(lambda, public_key) {
            return Err("Can't remove a node".into());
        }

        self.remove_node_from_tree(public_key)?;

        match self.update_branch_public_keys(lambda) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::RemoveNode(public_key);

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    pub fn update_branch(&mut self, changes: &BranchChanges) -> Result<(), String> {
        match &changes.change_type {
            BranchChangesType::UpdateKeys => self.update_branch_public_keys_using_changes(changes),
            BranchChangesType::AppendNode(node) => {
                self.find_place_and_append_node(node.clone())?;
                self.update_branch_public_keys_using_changes(changes)
            }
            BranchChangesType::MakeTemporal(public_key, temporal_lambda) => {
                match self.change_node_to_temporal(public_key.clone(), temporal_lambda.clone()) {
                    Ok(_) => Ok(()),
                    Err(msg) => Err(msg),
                }
            }
            BranchChangesType::RemoveNode(public_key) => {
                self.remove_node_from_tree(public_key.clone())?;

                self.update_branch_public_keys_using_changes(changes)
            }
        }
    }

    pub fn serialise(&self) -> Result<String, String> {
        match serde_json::to_string(&self) {
            Ok(json) => Ok(json),
            Err(e) => Err(format!("Failed to serialise: {:?}", e)),
        }
    }

    pub fn from_json(canonical_json: String) -> Result<Self, String> {
        let tree: Self = match serde_json::from_str(&canonical_json) {
            Ok(tree) => tree,
            Err(e) => return Err(format!("Failed to deserialize: {:?}", e)),
        };

        Ok(tree)
    }
}

pub struct ARTTrustedAgent {
    pub msk: MasterSecretKey,
    pub pk: PublicKey,
    pub secret_keys: Option<Vec<Fp12<Fq12Config>>>,
}

impl ARTTrustedAgent {
    pub fn new(msk: MasterSecretKey, pk: PublicKey) -> Self {
        ARTTrustedAgent {
            msk,
            pk,
            secret_keys: None,
        }
    }

    fn compute_secret_keys_and_ciphertexts(
        &self,
        identifiers_hashes: &Vec<ScalarField>,
    ) -> (Vec<Fp12<Fq12Config>>, Vec<ARTCiphertext>) {
        let mut rng = rand::thread_rng();

        let mut ciphertexts = Vec::new();
        let mut secret_keys = Vec::new();

        for hash in identifiers_hashes {
            let k = tools::random_non_neutral_scalar_field_element(&mut rng);

            let ciphertext = ARTCiphertext {
                c: self.pk.get_h().mul(k * self.msk.gamma.add(hash)),
            };

            let lambda = self.pk.v.pow(&k.into_bigint());

            secret_keys.push(lambda);
            ciphertexts.push(ciphertext);
        }

        (secret_keys, ciphertexts)
    }
    pub fn compute_art_and_ciphertexts<T: Into<Vec<u8>> + Clone + PartialEq>(
        &mut self,
        users_id: &Vec<UserIdentity<T>>,
    ) -> (ART, Vec<ARTCiphertext>, ARTRootKey) {
        let mut users_id_hash = Vec::new();
        for id in users_id {
            users_id_hash.push(id.hash_to_scalar_field());
        }

        let (secret_keys, ciphertexts) = self.compute_secret_keys_and_ciphertexts(&users_id_hash);
        self.secret_keys = Some(secret_keys.clone());
        let (tree, root_key) = ART::new_art_from_secrets(&secret_keys, &self.pk.get_h());

        (tree, ciphertexts, root_key)
    }

    pub fn get_recomputed_art(&self) -> ART {
        let (tree, _) =
            ART::new_art_from_secrets(&self.secret_keys.clone().unwrap(), &self.pk.get_h());

        tree
    }
}

#[derive(Debug)]
pub struct ARTUserAgent {
    pub root_key: ARTRootKey,
    pub tree: ART,
    pub lambda: Fp12<Fq12Config>,
}

impl ARTUserAgent {
    pub fn new(tree_json: String, ciphertext: ARTCiphertext, sk_id: SecretKey) -> Self {
        let mut tree = ART::from_json(tree_json).unwrap();

        let lambda = Bn254::pairing(ciphertext.c, sk_id.sk).0;
        let root_key = tree.recompute_root_key(lambda);

        Self {
            root_key,
            tree,
            lambda,
        }
    }

    pub fn update_key(&mut self) -> Result<(ARTRootKey, BranchChanges), String> {
        let mut rng = rand::thread_rng();
        let r = tools::random_non_neutral_scalar_field_element(&mut rng);

        let new_lambda = self.lambda.pow(&r.into_bigint());

        self.change_lambda(new_lambda)
    }

    pub fn append_node(
        &mut self,
        lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        match self.tree.append_node_by_lambda(lambda) {
            Ok((root_key, changes)) => {
                self.root_key = root_key.clone();
                Ok((root_key, changes))
            }
            Err(e) => Err(e),
        }
    }

    pub fn change_lambda(
        &mut self,
        new_lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        match self.tree.change_lambda(self.lambda, new_lambda) {
            Ok((root_key, changes)) => {
                self.lambda = new_lambda;
                self.root_key = root_key.clone();
                Ok((root_key, changes))
            }
            Err(e) => Err(e),
        }
    }

    pub fn make_temporal(&mut self, public_key: G1) -> Result<(ARTRootKey, BranchChanges), String> {
        let temporal_lambda = Fp12::<Fq12Config>::rand(&mut thread_rng());

        match self
            .tree
            .change_node_to_temporal(public_key, temporal_lambda)
        {
            Ok((root_key, changes)) => {
                self.root_key = root_key;
                Ok((root_key, changes))
            }
            Err(e) => Err(e),
        }
    }

    pub fn remove_node(&mut self, public_key: G1) -> Result<(ARTRootKey, BranchChanges), String> {
        match self.tree.remove_node(self.lambda, public_key) {
            Ok((root_key, changes)) => {
                self.root_key = root_key;
                Ok((root_key, changes))
            }
            Err(e) => Err(e),
        }
    }

    pub fn update_branch(&mut self, changes: &BranchChanges) -> Result<(), String> {
        let res = self.tree.update_branch(changes);
        self.root_key = self.tree.recompute_root_key(self.lambda);

        res
    }

    pub fn get_root_key(&self) -> ARTRootKey {
        self.root_key
    }

    pub fn serialise_art(&self) -> Result<String, String> {
        match serde_json::to_string(&self.tree) {
            Ok(json) => Ok(json),
            Err(e) => Err(format!("Failed to serialise: {:?}", e)),
        }
    }

    pub fn deserialize_art(&self, canonical_json: String) -> Result<ART, String> {
        let tree: ART = match serde_json::from_str(&canonical_json) {
            Ok(tree) => tree,
            Err(e) => return Err(format!("Failed to deserialize: {:?}", e)),
        };

        Ok(tree)
    }

    pub fn public_key(&self) -> G1 {
        self.tree.public_key_from_lambda(self.lambda)
    }

    pub fn can_remove(&mut self, public_key: G1) -> bool {
        self.tree.can_remove(self.lambda, public_key)
    }
}
