use crate::art::art_advanced_operations::ArtAdvancedOps;
use crate::art::artefacts::VerifierArtefacts;
use crate::art::{ArtLevel, ArtUpdateOutput, ProverArtefacts, PublicArt};
use crate::art_node::{ArtNode, LeafIterWithPath, LeafStatus, NodeIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregationNode, AggregationNodeIterWithPath, AggregationTree, TreeIterHelper,
    TreeNodeIterWithPath,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::mem;

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

impl<G, S> TryFrom<Vec<S>> for ArtSecrets<G>
where
    G: AffineRepr<ScalarField = S>,
{
    type Error = ArtError;

    fn try_from(secrets: Vec<G::ScalarField>) -> Result<Self, Self::Error> {
        if secrets.is_empty() {
            return Err(ArtError::InvalidInput);
        }

        Ok(Self(
            secrets.into_iter().map(|sk| ArtSecret::from(sk)).collect(),
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
            secrets: ArtSecrets::try_from(artefacts.secrets)?,
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
            secrets: ArtSecrets::try_from(artefacts.secrets)?,
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
            secrets: ArtSecrets::try_from(secrets)?,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    pub fn mut_public_art(&mut self) -> &mut PublicArt<G> {
        &mut self.public_art
    }

    pub fn root_secret_key(&self) -> G::ScalarField {
        self.secrets.0[self.secrets.0.len() - 1].key
    }

    pub fn root_public_key(&self) -> G {
        G::generator().mul(self.root_secret_key()).into_affine()
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
}

impl<G> ArtAdvancedOps<G, BranchChange<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        todo!()
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<BranchChange<G>, ArtError> {
        todo!()
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        todo!()
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        todo!()
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
    use crate::art_node::LeafIterWithPath;
    use crate::test_helper_tools::init_tracing;
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::cmp::{max, min};

    const TEST_GROUP_SIZE: usize = 100;

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
                    deserialized_art, private_art,
                    "Both users have the same view on the state of the art",
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
}
