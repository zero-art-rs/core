use crate::{
    errors::ARTError,
    helper_tools::{ark_de, ark_se, iota_function},
    types::{ARTNode, ARTRootKey},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::cmp::max;
use tracing::error;
use zkp::toolbox::Scalar;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,
    pub secrets: Vec<curve25519_dalek::Scalar>,
}

impl<G> ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn try_merge(&mut self, other: &ProverArtefacts<G>) -> Result<(), ARTError> {
        let mut merged_path = Vec::new();
        let mut merged_co_path = Vec::new();
        let mut merged_secrets = Vec::new();

        // Merge path
        for i in 0..max(self.path.len(), other.path.len()) {
            match (self.path.get(i), other.path.get(i)) {
                (Some(a), Some(b)) => merged_path.push(a.add(b).into_affine()),
                (Some(a), None) => merged_path.push(*a),
                (None, Some(b)) => merged_path.push(*b),
                (None, None) => {}
            }
        }

        // Merge secrets
        for i in 0..max(self.path.len(), other.path.len()) {
            match (self.secrets.get(i), other.secrets.get(i)) {
                (Some(a), Some(b)) => merged_secrets.push(a + b),
                (Some(a), None) => merged_secrets.push(*a),
                (None, Some(b)) => merged_secrets.push(*b),
                (None, None) => {}
            }
        }

        // Merge co_path
        for i in 0..max(self.co_path.len(), other.co_path.len()) {
            match (self.co_path.get(i), other.co_path.get(i)) {
                (Some(a), Some(b)) => merged_co_path.push(a.add(b).into_affine()),
                (Some(a), None) => merged_co_path.push(*a),
                (None, Some(b)) => merged_co_path.push(*b),
                (None, None) => {}
            }
        }

        self.path = merged_path;
        self.co_path = merged_co_path;
        self.secrets = merged_secrets;

        Ok(())
    }
}

impl<G> Default for ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    fn default() -> Self {
        Self {
            path: Vec::new(),
            secrets: Vec::new(),
            co_path: Vec::new(),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub path: Vec<G>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_path: Vec<G>,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}

impl<G> PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub fn compute_next_layer_of_tree(
        level_nodes: &mut Vec<ARTNode<G>>,
        level_secrets: &mut Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Vec<ARTNode<G>>, Vec<G::ScalarField>), ARTError> {
        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();

        // iterate until level_nodes is empty, then swap it with the next layer
        while level_nodes.len() > 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

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
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    pub fn fit_leaves_in_one_level(
        mut level_nodes: Vec<ARTNode<G>>,
        mut level_secrets: Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Vec<ARTNode<G>>, Vec<G::ScalarField>), ARTError> {
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
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

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

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        if secrets.is_empty() {
            return Err(ARTError::InvalidInput);
        }
        let mut level_nodes = Vec::new();
        let mut level_secrets = Vec::new();

        // leaves of the tree
        for leaf_secret in secrets {
            let node = ARTNode::new_leaf(generator.mul(leaf_secret).into_affine());

            level_nodes.push(node);
            level_secrets.push(*leaf_secret);
        }

        // fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets, generator)?;
        }

        // iterate by levels. Go from current level to upper level
        while level_nodes.len() > 1 {
            (level_nodes, level_secrets) =
                Self::compute_next_layer_of_tree(&mut level_nodes, &mut level_secrets, generator)?;
        }

        let root = level_nodes.remove(0);
        let root_key = ARTRootKey {
            key: level_secrets.remove(0),
            generator: *generator,
        };

        let art = Self {
            root: Box::new(root),
            generator: *generator,
        };

        Ok((art, root_key))
    }

    pub fn to_string(&self) -> Result<String, ARTError> {
        serde_json::to_string(&self).map_err(ARTError::SerdeJson)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(self).map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(ARTError::Postcard)
    }

    pub fn from_string(canonical_json: &str) -> Result<Self, ARTError> {
        serde_json::from_str(canonical_json).map_err(ARTError::SerdeJson)
    }
}
