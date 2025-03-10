// Asynchronous Ratchet Tree implementation

use crate::ibbe_del7::{MasterSecretKey, PublicKey, UserIdentity};
use crate::tools;
use ark_bn254::{
    Bn254, Config, Fq12, Fq12Config, G1Projective as G1, G2Projective as G2, fq::Fq, fq2::Fq2,
    fr::Fr as ScalarField, fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};
use ark_ec::pairing::PairingOutput;
use ark_ec::short_weierstrass::Projective;
use ark_ff::{Field, Fp12, Fp256, MontBackend, PrimeField, ToConstraintField};
use std::ops::{Add, Mul};
use std::option;

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
}

#[derive(Debug)]
pub struct ART {
    root: ARTNode,
    length: usize,
}

impl ART {
    pub fn from(
        leaves_secret: &Vec<Fp256<MontBackend<FrConfig, 4>>>,
        point: &G1Projective<Config>,
    ) -> Self {
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // Compute first layer of the tree
        for leaf in leaves_secret {
            let node = ARTNode {
                val: point.mul(leaf),
                l: None,
                r: None,
            };
            level_nodes.push(node);
            level_secrets.push(leaf.clone());
        }

        let mut leaves = Vec::new();
        for node in &level_nodes {
            leaves.push(node)
        }

        // iterate by levels
        while level_nodes.len() > 1 {
            let mut upper_level_nodes = Vec::new();
            let mut upper_level_secrets = Vec::new();

            // iterate until tree_level_nodes is empty, then swap it with the next layer
            while level_nodes.len() > 1 {
                let left_node = level_nodes.remove(0);
                let right_node = level_nodes.remove(0);
                level_secrets.remove(0); // skip the first secret

                let secret = left_node
                    .val
                    .mul(level_secrets.remove(0))
                    .to_string()
                    .into_bytes();
                let secret_hash = tools::sha512_from_byte_vec_to_scalar_field(&secret);
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
            root,
            length: leaves_secret.len(),
        }
    }

    pub fn compute_hash(&self) -> Fp256<MontBackend<FrConfig, 4>> {
        self.root.compute_hash()
    }
}

pub struct ARTAgent {
    // suk:
    // ik:
}

impl ARTAgent {
    // pub fn new() -> Self { Self {} }
    pub fn setup_art(msk: &MasterSecretKey, pk: &PublicKey, users_id: &Vec<UserIdentity>) {
        let mut users_id_hash = Vec::new();
        for id in users_id {
            users_id_hash.push(id.hash_to_scalar_field());
        }

        let mut rng = rand::thread_rng();

        let mut random_k_values: Vec<Fp256<MontBackend<FrConfig, 4>>> = Vec::new();
        let mut ciphertexts: Vec<G1Projective<Config>> = Vec::new();

        let k0 = tools::random_non_neutral_scalar_field_element(&mut rng);
        let mut leaves = vec![tools::sha512_from_byte_vec_to_scalar_field(
            &pk.v.pow(&k0.into_bigint()).to_string().into_bytes(),
        )];

        for id_hash in users_id_hash {
            let k = tools::random_non_neutral_scalar_field_element(&mut rng);

            random_k_values.push(k);
            ciphertexts.push(pk.get_h().mul(k * msk.gamma.add(&id_hash)));
            leaves.push(tools::sha512_from_byte_vec_to_scalar_field(
                &pk.v.pow(&k.into_bigint()).to_string().into_bytes(),
            ));
        }

        let root = ART::from(&leaves, &pk.get_h());

        println!("{:?}", root);
        println!("{:?}", root.compute_hash());
    }
}
