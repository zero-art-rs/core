use crate::art::art_node::{ArtNode, NodeIterWithPath};
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_std::rand::Rng;
use cortado::CortadoAffine;

/// A collection of helper methods to interact with tree.
///
/// This trait provides access to the root node and other leaves. There are several
/// similar methods, which differ only on input type. They can be differentiated by the postfix.
/// If the method takes as input `NodeIndex`, then there is no specific postfixes. If it takes
/// a slice `[Direction]`, then the postfix is `_at`. The last postfix `_with` is for methods,
/// which searches for a node with the provided public key.
///
/// This trait can be implemented to any type, that reefers to `ArtNode`.
///
/// # Type Parameters
/// * `G` - The affine curve representation used for nodes in the tree.
pub trait TreeMethods<G>
where
    G: AffineRepr,
{
    /// Return the reference on the root node of the tree.
    fn get_root(&self) -> &ArtNode<G>;

    /// Return the mutable reference on the root node of the tree
    fn get_mut_root(&mut self) -> &mut ArtNode<G>;

    /// If exists, returns a reference on the node with the given index, in correspondence to the
    /// root node. Else return `ArtError`.
    fn get_node(&self, index: &NodeIndex) -> Result<&ArtNode<G>, ArtError> {
        self.get_node_at(&index.get_path()?)
    }

    /// If exists, returns mutable reference on the node with the given index, in correspondence
    /// to the root node. Else return `ArtError`.
    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ArtNode<G>, ArtError> {
        self.get_mut_node_at(&index.get_path()?)
    }

    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    fn get_node_at(&self, path: &[Direction]) -> Result<&ArtNode<G>, ArtError> {
        let mut node = self.get_root();
        for direction in path {
            if let Some(child_node) = node.get_child(*direction) {
                node = child_node;
            } else {
                return Err(ArtError::PathNotExists);
            }
        }

        Ok(node)
    }

    /// If exists, returns a mutable reference on the node at the end of the given `path` form root. Else return `ArtError`.
    fn get_mut_node_at(&mut self, path: &[Direction]) -> Result<&mut ArtNode<G>, ArtError> {
        let mut node = self.get_mut_root();
        for direction in path {
            node = node
                .get_mut_child(*direction)
                .ok_or(ArtError::PathNotExists)?;
        }

        Ok(node)
    }

    /// If exists, return a reference on the leaf with the provided `public_key`. Else return `ArtError`.
    fn get_leaf_with(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// If exists, return a mutable reference on the node with the provided `public_key`. Else return `ArtError`.
    fn get_node_with(&self, public_key: G) -> Result<&ArtNode<G>, ArtError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.get_public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ArtError::PathNotExists)
    }

    /// Searches for a leaf with the provided `public_key`. If there is no such leaf, retutrn `ArtError`.
    fn get_path_to_leaf_with(&self, public_key: G) -> Result<Vec<Direction>, ArtError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(&public_key) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        Err(ArtError::PathNotExists)
    }
}

impl<G> TreeMethods<G> for ArtNode<G>
where
    G: AffineRepr,
{
    fn get_root(&self) -> &ArtNode<G> {
        self
    }

    fn get_mut_root(&mut self) -> &mut ArtNode<G> {
        self
    }
}

impl<G> TreeMethods<G> for PublicArt<G>
where
    G: AffineRepr,
{
    fn get_root(&self) -> &ArtNode<G> {
        self.tree_root.get_root()
    }

    fn get_mut_root(&mut self) -> &mut ArtNode<G> {
        self.tree_root.get_mut_root()
    }
}

impl<G> TreeMethods<G> for PrivateArt<G>
where
    G: AffineRepr,
{
    fn get_root(&self) -> &ArtNode<G> {
        self.public_art.tree_root.get_root()
    }

    fn get_mut_root(&mut self) -> &mut ArtNode<G> {
        self.public_art.tree_root.get_mut_root()
    }
}

impl TreeMethods<CortadoAffine> for PublicZeroArt {
    fn get_root(&self) -> &ArtNode<CortadoAffine> {
        self.public_art.tree_root.get_root()
    }

    fn get_mut_root(&mut self) -> &mut ArtNode<CortadoAffine> {
        self.public_art.tree_root.get_mut_root()
    }
}

impl<'a, R> TreeMethods<CortadoAffine> for PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    fn get_root(&self) -> &ArtNode<CortadoAffine> {
        self.private_art.public_art.tree_root.get_root()
    }

    fn get_mut_root(&mut self) -> &mut ArtNode<CortadoAffine> {
        self.private_art.public_art.tree_root.get_mut_root()
    }
}
