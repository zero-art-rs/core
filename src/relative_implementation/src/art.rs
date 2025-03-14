// Asynchronous Ratchet Tree implementation

use crate::ibbe_del7::{MasterSecretKey, PublicKey, SecretKey, UserIdentity};
use crate::tools;
use ark_bn254::{
    Bn254, Config, Fq12Config, G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField,
    fr::FrConfig,
};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{Field, Fp12, Fp12Config, Fp256, MontBackend, PrimeField, ToConstraintField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::iterable::Iterable;
use ark_std::{One, UniformRand, Zero};
use serde::{Deserialize, Serialize};
use serde_json;
use std::ops::{Add, Mul};

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

#[derive(Debug, Clone, Copy)]
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
pub struct BranchChanges {
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
}

impl ARTNode {
    pub fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    pub fn get_left(&self) -> &Box<ARTNode> {
        match &self.l {
            Some(l) => l,
            None => panic!("Leaf doesn't have a left child."),
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
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ART {
    root: Box<ARTNode>,
    pub root_key: Option<ARTRootKey>,
}

impl ART {
    pub fn set_root_key(&mut self, root_key: ARTRootKey) {
        self.root_key = Some(root_key);
    }

    pub fn remove_root_key(&mut self) -> ARTRootKey {
        let root_key = self.root_key.unwrap().clone();
        self.root_key = None;

        root_key
    }

    fn compute_next_layer(
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
            let secret_hash = tools::sha512_from_byte_vec_to_scalar_field(
                &common_secret.to_string().into_bytes(),
            );

            let node = ARTNode {
                public_key: generator.mul(&secret_hash),
                l: Some(Box::new(left_node)),
                r: Some(Box::new(right_node)),
            };

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

    pub fn new_art_from_secrets(secrets: &Vec<Fp12<Fq12Config>>, generator: &G1) -> Self {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            // compute as hash to resolve type conflict
            let secret = tools::sha512_from_byte_vec_to_scalar_field(
                &leaf_secret.clone().to_string().into_bytes(),
            );

            let node = ARTNode {
                public_key: generator.mul(secret),
                l: None,
                r: None,
            };

            level_nodes.push(node);
            level_secrets.push(secret);
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            (level_nodes, level_secrets) =
                ART::compute_next_layer(&mut level_nodes, &mut level_secrets, generator);
        }

        let root = level_nodes.remove(0);
        let root_key = ARTRootKey {
            key: level_secrets.remove(0),
            lambda: None,
            generator: generator.clone(),
        };

        ART {
            root: Box::new(root),
            root_key: Some(root_key),
            // root_key: None, it is hard to remove
        }
    }

    pub fn get_root(&self) -> &Box<ARTNode> {
        &self.root
    }

    pub fn get_co_path_values(&self, user_public_key: G1) -> Result<Vec<G1>, String> {
        let (path_nodes, next_node) = self.get_path(user_public_key).unwrap();

        let mut co_path_values = Vec::new();

        for i in (0..path_nodes.len() - 1).rev() {
            let node = path_nodes.get(i).unwrap();
            let direction = next_node.get(i).unwrap();

            match direction {
                Direction::Left => co_path_values.push(node.get_right().public_key),
                Direction::Right => co_path_values.push(node.get_left().public_key),
                _ => panic!("Unexpected direction"),
            }
        }

        Ok(co_path_values)
    }

    pub fn get_path(&self, user_val: G1) -> Result<(Vec<&ARTNode>, Vec<Direction>), String> {
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut discovered = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.public_key.eq(&user_val) {
                    return Ok((path, discovered));
                } else {
                    path.pop();
                    discovered.pop();
                }
            } else {
                match discovered.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right().as_ref());

                        discovered.push(Direction::Right);
                        discovered.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left().as_ref());

                        discovered.push(Direction::Left);
                        discovered.push(Direction::NoDirection);
                    }
                }
            }
        }

        Err("Can't find a path.".to_string())
    }

    pub fn recover_root_key(&mut self, lambda: Fp12<Fq12Config>, generator: &G1) -> ARTRootKey {
        let mut secret_key =
            tools::sha512_from_byte_vec_to_scalar_field(&lambda.to_string().into_bytes());

        let user_public_key = generator.mul(secret_key);
        let co_path_values = self.get_co_path_values(user_public_key).unwrap();

        //initialize with zero, to resolve compile error
        let mut upper_level_public_key = G1::zero();

        for public_keys in co_path_values.iter() {
            secret_key = tools::sha512_from_byte_vec_to_scalar_field(
                &public_keys.mul(secret_key).to_string().into_bytes(),
            );
            upper_level_public_key = generator.mul(secret_key);
        }

        let key = ARTRootKey {
            key: secret_key,
            lambda: Some(lambda),
            generator: generator.clone(),
        };
        self.root_key = Some(key);

        key
    }

    pub fn compute_root_key(
        &mut self,
        ciphertext: ARTCiphertext,
        sk_id: SecretKey,
        generator: &G1,
    ) -> ARTRootKey {
        let lambda = Bn254::pairing(ciphertext.c, sk_id.sk).0;

        self.recover_root_key(lambda, generator)
    }

    pub fn change_lambda(
        &mut self,
        new_lambda: Fp12<Fq12Config>,
    ) -> Result<(ARTRootKey, BranchChanges), String> {
        let generator = self.root_key.unwrap().generator;

        let old_lambda = self.root_key.unwrap().lambda.unwrap();
        let old_secret_key =
            tools::sha512_from_byte_vec_to_scalar_field(&old_lambda.to_string().into_bytes());
        let old_public_key = generator.mul(old_secret_key);

        let (_, mut next) = self.get_path(old_public_key)?;

        let mut changes = BranchChanges {
            public_keys: Vec::new(),
            next: next.clone(),
        };

        let mut secret_key =
            tools::sha512_from_byte_vec_to_scalar_field(&new_lambda.to_string().into_bytes());
        let mut public_key = generator.mul(secret_key);

        next.pop();
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
            secret_key =
                tools::sha512_from_byte_vec_to_scalar_field(&secret.to_string().into_bytes());
            public_key = generator.mul(&secret_key);
        }

        self.root.set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: secret_key,
            lambda: Some(new_lambda),
            generator: generator.clone(),
        };

        self.root_key = Some(key);

        Ok((key, changes))
    }

    pub fn update_key(&mut self) -> Result<(ARTRootKey, BranchChanges), String> {
        let mut rng = ark_std::rand::thread_rng();
        let r = tools::random_non_neutral_scalar_field_element(&mut rng);

        let new_lambda = self.root_key.unwrap().lambda.unwrap().pow(&r.into_bigint());

        self.change_lambda(new_lambda)
    }

    pub fn update_branch(&mut self, changes: &BranchChanges) -> Result<(), String> {
        let mut current_node = self.root.as_mut();
        for i in (0..changes.next.len() - 1) {
            current_node.set_public_key(changes.public_keys[i].clone());

            current_node = current_node.get_mut_child(changes.next.get(i).unwrap())?;
        }

        current_node.set_public_key(changes.public_keys[changes.next.len() - 1].clone());

        self.recover_root_key(
            self.root_key.unwrap().lambda.unwrap(),
            &self.root_key.unwrap().generator,
        );

        Ok(())
    }
}

pub struct ARTAgent {
    pub msk: MasterSecretKey,
    pub pk: PublicKey,
    pub secret_keys: Option<Vec<Fp12<Fq12Config>>>,
}

impl ARTAgent {
    pub fn new(msk: MasterSecretKey, pk: PublicKey) -> Self {
        ARTAgent {
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
        let tree = ART::new_art_from_secrets(&secret_keys, &self.pk.get_h());
        let root_key = tree.root_key.unwrap();

        (tree, ciphertexts, root_key)
    }

    pub fn get_recomputed_art(&self) -> ART {
        let tree = ART::new_art_from_secrets(&self.secret_keys.clone().unwrap(), &self.pk.get_h());

        tree
    }
}
