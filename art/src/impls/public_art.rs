use crate::errors::ARTError;
use crate::helper_tools::iota_function;
use crate::types::{ARTRootKey, PrivateART};
use crate::{
    traits::ARTPublicView,
    types::{ARTNode, PublicART},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use std::mem;

pub(crate) type ArtLevel<G> = (Vec<ARTNode<G>>, Vec<<G as AffineRepr>::ScalarField>);

impl<G> PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub fn compute_next_layer_of_tree(
        level_nodes: &mut Vec<ARTNode<G>>,
        level_secrets: &mut Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<ArtLevel<G>, ARTError> {
        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();

        // iterate until level_nodes is empty, then swap it with the next layer
        while level_nodes.len() > 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let ark_common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

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
    ) -> Result<ArtLevel<G>, ARTError> {
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

            let ark_common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

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

impl<G> ARTPublicView<G> for PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_root(&self) -> &ARTNode<G> {
        &self.root
    }

    fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>> {
        &mut self.root
    }

    fn get_generator(&self) -> G {
        self.generator
    }

    fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>> {
        mem::replace(&mut self.root, new_root)
    }
}

impl<G> From<PrivateART<G>> for PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn from(mut other: PrivateART<G>) -> Self {
        let root = other.replace_root(Box::new(ARTNode::default()));

        Self {
            root,
            generator: other.get_generator(),
        }
    }
}
