// Asynchronous Ratchet Tree implementation

use crate::ibbe_del7::{MasterSecretKey, PublicKey, SecretKey, UserIdentity};
use crate::tools;
use ark_bn254::{
    Bn254, Config, G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ec::short_weierstrass::Projective;
use ark_ff::{Field, Fp12, Fp256, MontBackend, PrimeField, ToConstraintField};
use ark_std::iterable::Iterable;
use ark_std::{One, UniformRand, Zero};
use std::ops::{Add, Mul};

#[derive(Debug)]
struct ARTNode {
    val: G1Projective<Config>,
    l: Option<Box<ARTNode>>,
    r: Option<Box<ARTNode>>,
}

enum Direction {
    NoDirection,
    Left,
    Right,
}

#[derive(Debug, Clone, Copy)]
pub struct ARTCiphertext {
    pub c: Projective<ark_bn254::g1::Config>,
}

#[derive(Debug, Clone, Copy)]
pub struct ARTRootKey {
    pub key: ScalarField,
}

pub struct ARTAgent {
    pub msk: MasterSecretKey,
    pub pk: PublicKey,
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

    pub fn get_right(&self) -> &Box<ARTNode> {
        match &self.r {
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
}

#[derive(Debug)]
pub struct ART {
    root: Box<ARTNode>,
    pub root_key: Option<ARTRootKey>,
}

impl ART {
    pub fn new_art_from_secrets(
        secrets: &Vec<Fp256<MontBackend<FrConfig, 4>>>,
        generator: &G1Projective<Config>,
    ) -> Self {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            let node = ARTNode {
                val: generator.mul(leaf_secret),
                l: None,
                r: None,
            };
            level_nodes.push(node);
            level_secrets.push(leaf_secret.clone());
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            let mut upper_level_nodes = Vec::new();
            let mut upper_level_secrets = Vec::new();

            // iterate until level_nodes is empty, then swap it with the next layer
            while level_nodes.len() > 1 {
                let left_node = level_nodes.remove(0);
                let right_node = level_nodes.remove(0);

                level_secrets.remove(0); // skip the first secret

                let common_secret = left_node.val.mul(level_secrets.remove(0));
                let secret_hash = tools::sha512_from_byte_vec_to_scalar_field(
                    &common_secret.to_string().into_bytes(),
                );

                let node = ARTNode {
                    val: generator.mul(&secret_hash),
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

            level_nodes = upper_level_nodes;
            level_secrets = upper_level_secrets;
        }

        let root = level_nodes.remove(0);
        let root_key = ARTRootKey {
            key: level_secrets.remove(0),
        };

        ART {
            root: Box::new(root),
            root_key: Some(root_key),
        }
    }

    pub fn get_root(&self) -> &Box<ARTNode> {
        &self.root
    }

    pub fn get_co_path_values(
        &self,
        user_val: G1Projective<Config>,
    ) -> Result<Vec<G1Projective<Config>>, String> {
        let (path_nodes, next_node_directions) = self.get_path(user_val).unwrap();

        let mut co_path_values = Vec::new();

        for i in (0..path_nodes.len() - 1).rev() {
            let node = path_nodes.get(i).unwrap();
            let direction = next_node_directions.get(i).unwrap();

            match direction {
                Direction::Left => co_path_values.push(node.get_right().val),
                Direction::Right => co_path_values.push(node.get_left().val),
                _ => panic!("Unexpected direction"),
            }
        }

        Ok(co_path_values)
    }

    pub fn get_path(
        &self,
        user_val: G1Projective<Config>,
    ) -> Result<(Vec<&ARTNode>, Vec<Direction>), String> {
        let root = self.get_root();

        let mut co_path = vec![root.as_ref()];
        let mut discovered_directions = vec![Direction::NoDirection];

        while !co_path.is_empty() {
            let last_node = co_path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.val.eq(&user_val) {
                    return Ok((co_path, discovered_directions));
                } else {
                    co_path.pop();
                    discovered_directions.pop();
                }
            } else {
                match discovered_directions.pop().unwrap() {
                    Direction::Left => {
                        co_path.push(last_node.get_right().as_ref());

                        discovered_directions.push(Direction::Right);
                        discovered_directions.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        co_path.pop();
                    }
                    Direction::NoDirection => {
                        co_path.push(last_node.get_left().as_ref());

                        discovered_directions.push(Direction::Left);
                        discovered_directions.push(Direction::NoDirection);
                    }
                }
            }
        }

        Err("Can't find a path.".to_string())
    }

    pub fn compute_key(
        &self,
        ciphertext: ARTCiphertext,
        sk_id: SecretKey,
        pk: &PublicKey,
    ) -> Fp256<MontBackend<FrConfig, 4>> {
        let lambda = Bn254::pairing(ciphertext.c, sk_id.sk).0;
        let mut secret_key =
            tools::sha512_from_byte_vec_to_scalar_field(&lambda.to_string().into_bytes());

        let user_public_key = pk.get_h().mul(secret_key);
        let co_path_values = self.get_co_path_values(user_public_key).unwrap();

        //initialize with zero, to resolve compile error
        let mut upper_level_value = G1::zero();

        for public_keys in co_path_values.iter() {
            secret_key = tools::sha512_from_byte_vec_to_scalar_field(
                &public_keys.mul(secret_key).to_string().into_bytes(),
            );
            upper_level_value = pk.get_h().mul(secret_key);
        }

        // tools::sha512_from_byte_vec_to_scalar_field(&upper_level_value.to_string().into_bytes())
        secret_key
    }
}

impl ARTAgent {
    pub fn new(msk: MasterSecretKey, pk: PublicKey) -> Self {
        ARTAgent { msk, pk }
    }

    fn compute_secret_keys_and_ciphertexts(
        &self,
        identifiers_hash: &Vec<ScalarField>,
    ) -> (Vec<ScalarField>, Vec<ARTCiphertext>) {
        let mut rng = rand::thread_rng();

        let mut ciphertexts = Vec::new();
        let mut secret_keys = Vec::new();

        for hash in identifiers_hash {
            let k = tools::random_non_neutral_scalar_field_element(&mut rng);

            let ciphertext = ARTCiphertext {
                c: self.pk.get_h().mul(k * self.msk.gamma.add(hash)),
            };

            let lambda = self.pk.v.pow(&k.into_bigint());
            let secret =
                tools::sha512_from_byte_vec_to_scalar_field(&lambda.to_string().into_bytes());

            secret_keys.push(secret);
            ciphertexts.push(ciphertext);
        }

        (secret_keys, ciphertexts)
    }
    pub fn compute_art_and_ciphertexts<T: Into<Vec<u8>> + Clone + PartialEq>(
        &self,
        users_id: &Vec<UserIdentity<T>>,
    ) -> (ART, Vec<ARTCiphertext>) {
        let mut users_id_hash = Vec::new();
        for id in users_id {
            users_id_hash.push(id.hash_to_scalar_field());
        }

        let (secret_keys, ciphertexts) = self.compute_secret_keys_and_ciphertexts(&users_id_hash);

        let tree = ART::new_art_from_secrets(&secret_keys, &self.pk.get_h());

        (tree, ciphertexts)
    }
}
