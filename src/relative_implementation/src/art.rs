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

impl ARTNode {
    pub fn compute_hash(&self) -> Fp256<MontBackend<FrConfig, 4>> {
        tools::sha512_from_byte_vec_to_scalar_field(&self.val.to_string().into_bytes())
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

    pub fn get_right(&self) -> &Box<ARTNode> {
        match &self.r {
            Some(r) => r,
            None => panic!("Leaf doesn't have a right child."),
        }
    }
}

#[derive(Debug)]
pub struct ART {
    root: Box<ARTNode>,
    length: usize,
}

impl ART {
    fn compute_level_nodes_and_secrets_from_(&self) {}
    pub fn from(
        leaves_secret: &Vec<Fp256<MontBackend<FrConfig, 4>>>,
        point: &G1Projective<Config>,
    ) -> Self {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // Compute first layer of the tree
        for leaf_secret in leaves_secret {
            let node = ARTNode {
                val: point.mul(leaf_secret),
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

            // iterate until tree_level_nodes is empty, then swap it with the next layer
            while level_nodes.len() > 1 {
                let left_node = level_nodes.remove(0);
                let right_node = level_nodes.remove(0);
                level_secrets.remove(0); // skip the first secret

                let common_secret = left_node.val.mul(level_secrets.remove(0));
                let secret_hash = tools::sha512_from_byte_vec_to_scalar_field(
                    &common_secret.to_string().into_bytes(),
                );
                let node = ARTNode {
                    val: point.mul(&secret_hash),
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

        ART {
            root: Box::new(root),
            length: leaves_secret.len(),
        }
    }

    pub fn compute_hash(&self) -> Fp256<MontBackend<FrConfig, 4>> {
        self.root.compute_hash()
    }

    pub fn get_root(&self) -> &Box<ARTNode> {
        &self.root
    }
}

enum Direction {
    NoDirection,
    Left,
    Both,
}

#[derive(Debug, Clone, Copy)]
pub struct ARTCiphertext {
    c: Projective<ark_bn254::g1::Config>,
}

pub struct ARTAgent {
    pub tree: Option<ART>,
    pub msk: Option<MasterSecretKey>,
    pub pk: PublicKey,
    pub user_id: UserIdentity,
    // suk:
    // ik:
}

impl ARTAgent {
    pub fn setup(msk: Option<MasterSecretKey>, pk: PublicKey, user_id: UserIdentity) -> Self {
        ARTAgent {
            tree: None,
            msk,
            pk,
            user_id,
        }
    }

    pub fn setup_art(&mut self, users_id: &Vec<UserIdentity>) -> Vec<ARTCiphertext> {
        let mut users_id_hash = Vec::new();
        for id in users_id {
            users_id_hash.push(id.hash_to_scalar_field());
        }

        let mut rng = rand::thread_rng();

        let mut random_k_values = Vec::new();
        let mut ciphertexts = Vec::new();
        let mut leaves = Vec::new();

        for id_hash in users_id_hash {
            let k = tools::random_non_neutral_scalar_field_element(&mut rng);

            random_k_values.push(k);
            ciphertexts.push(ARTCiphertext {
                c: self
                    .pk
                    .get_h()
                    .mul(k * self.msk.unwrap().gamma.add(&id_hash)),
            });
            let lambda = self.pk.v.pow(&k.into_bigint());
            leaves.push(tools::sha512_from_byte_vec_to_scalar_field(
                &lambda.to_string().into_bytes(),
            ));
        }

        let tree = ART::from(&leaves, &self.pk.get_h());

        self.tree = Some(tree);

        ciphertexts
    }

    pub fn compute_hash(&self) -> Fp256<MontBackend<FrConfig, 4>> {
        match &self.tree {
            Some(tree) => tree.compute_hash(),
            None => panic!("Agent doesn't have a tree."),
        }
    }

    pub fn get_co_path_values(
        &self,
        user_val: G1Projective<Config>,
    ) -> Result<Vec<G1Projective<Config>>, String> {
        let tree = match &self.tree {
            Some(tree) => tree,
            None => panic!("No tree"),
        };

        let root = tree.get_root();

        // co_path is a stack of nodes fot search in depth, and discovered_directions is a
        // set of flags. If set to NoDirection, then no child node was visited, if it is
        // Left, then the left one was visited, and if it is Both, then both were visited.
        let mut co_path = vec![root.as_ref()];
        let mut discovered_directions = vec![Direction::NoDirection];

        while !co_path.is_empty() {
            let last_node = co_path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.val.eq(&user_val) {
                    // found the leaf, roll back the vector
                    let mut co_path_values = Vec::new();

                    for i in (0..co_path.len() - 1).rev() {
                        let node = co_path.get(i).unwrap();
                        let direction = discovered_directions.get(i).unwrap();

                        match direction {
                            Direction::Left => co_path_values.push(node.get_right().val),
                            Direction::Both => co_path_values.push(node.get_left().val),
                            _ => panic!("Unexpected direction"),
                        }
                    }

                    return Ok(co_path_values);
                } else {
                    co_path.pop();
                    discovered_directions.pop();
                }
            } else {
                match discovered_directions.pop().unwrap() {
                    Direction::Left => {
                        co_path.push(last_node.get_right().as_ref());

                        discovered_directions.push(Direction::Both);
                        discovered_directions.push(Direction::NoDirection);
                    }
                    Direction::Both => {
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

    pub fn tree_gen(
        &self,
        ciphertext: ARTCiphertext,
        sk_id: SecretKey,
    ) -> Fp256<MontBackend<FrConfig, 4>> {
        let lambda = Bn254::pairing(ciphertext.c, sk_id.sk).0;
        let mut secret_hash =
            tools::sha512_from_byte_vec_to_scalar_field(&lambda.to_string().into_bytes());

        let user_leaf_val = self.pk.get_h().mul(secret_hash);
        let co_path_values = self.get_co_path_values(user_leaf_val).unwrap();

        //initialize with zero, to resolve compile error
        let mut upper_level_value = G1::zero();

        for point in co_path_values.iter() {
            upper_level_value = point.mul(secret_hash);
            secret_hash = tools::sha512_from_byte_vec_to_scalar_field(
                &upper_level_value.to_string().into_bytes(),
            );
            upper_level_value = self.pk.get_h().mul(secret_hash);
        }

        tools::sha512_from_byte_vec_to_scalar_field(&upper_level_value.to_string().into_bytes())
    }
}
