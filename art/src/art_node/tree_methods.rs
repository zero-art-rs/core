use crate::art::{ArtNodePreview, PrivateArt, PublicArt};
// use crate::art::{PrivateZeroArt, PublicZeroArt};
use crate::art_node::{ArtNode, NodeIterWithPath};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use tracing::debug;

pub(crate) trait TreeNode {
    fn child_node(&self, dir: Direction) -> Option<&Self>;
    fn mut_child_node(&mut self, dir: Direction) -> Option<&mut Self>;
}

pub trait TreeNodeRef
where
    Self: Sized,
{
    fn child_node(&self, dir: Direction) -> Option<Self>;
}

/// A collection of helper methods to interact with tree.
///
/// This trait provides access to the root, internal nodes and leaves. There are several
/// similar methods, which differ by input type. They can be differentiated by the postfix.
/// If the method takes as input `NodeIndex`, then there is no specific postfixes. If it takes
/// a slice `[Direction]`, then the postfix is `_at`. The last postfix `_with` is for methods,
/// which searches for a node with the provided public key.
///
/// This trait can be implemented to any type, that reefers to `ArtNode`.
///
/// # Type Parameters
/// * `G` - The affine curve representation used for nodes in the tree.
pub trait TreeMethods {
    type Node: TreeNode;

    /// Return the reference on the root node of the tree.
    fn root(&self) -> &Self::Node;

    /// Return the mutable reference on the root node of the tree
    fn mut_root(&mut self) -> &mut Self::Node;

    /// If exists, returns a reference on the node with the given index, in correspondence to the
    /// root node. Else return `ArtError`.
    fn node(&self, index: &NodeIndex) -> Result<&Self::Node, ArtError> {
        self.node_at(&index.get_path()?)
    }

    /// If exists, returns mutable reference on the node with the given index, in correspondence
    /// to the root node. Else return `ArtError`.
    fn mut_node(&mut self, index: &NodeIndex) -> Result<&mut Self::Node, ArtError> {
        self.mut_node_at(&index.get_path()?)
    }

    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    fn node_at(&self, path: &[Direction]) -> Result<&Self::Node, ArtError> {
        let mut node = self.root();
        for direction in path {
            if let Some(child_node) = node.child_node(*direction) {
                node = child_node;
            } else {
                return Err(ArtError::PathNotExists);
            }
        }

        Ok(node)
    }

    /// If exists, returns a mutable reference on the node at the end of the given `path` form root. Else return `ArtError`.
    fn mut_node_at(&mut self, path: &[Direction]) -> Result<&mut Self::Node, ArtError> {
        let mut node = self.mut_root();
        for direction in path {
            node = node
                .mut_child_node(*direction)
                .ok_or(ArtError::PathNotExists)?;
        }

        Ok(node)
    }
}

pub trait TreeMethodsRef {
    type Node: TreeNodeRef;

    /// Return the reference on the root node of the tree.
    fn root(&self) -> Self::Node;

    /// If exists, returns a reference on the node with the given index, in correspondence to the
    /// root node. Else return `ArtError`.
    fn node(&self, index: &NodeIndex) -> Result<Self::Node, ArtError> {
        self.node_at(&index.get_path()?)
    }

    /// If exists, returns reference on the node at the end of the given path form root. Else return `ArtError`.
    fn node_at(&self, path: &[Direction]) -> Result<Self::Node, ArtError> {
        let mut node = self.root();
        for direction in path {
            if let Some(child_node) = node.child_node(*direction) {
                node = child_node;
            } else {
                return Err(ArtError::PathNotExists);
            }
        }

        Ok(node)
    }
}

impl<G> TreeNode for ArtNode<G>
where
    G: AffineRepr,
{
    fn child_node(&self, dir: Direction) -> Option<&Self> {
        self.child(dir)
    }

    fn mut_child_node(&mut self, dir: Direction) -> Option<&mut Self> {
        self.mut_child(dir)
    }
}

impl<G> TreeMethods for ArtNode<G>
where
    G: AffineRepr,
{
    type Node = ArtNode<G>;

    fn root(&self) -> &ArtNode<G> {
        self
    }

    fn mut_root(&mut self) -> &mut ArtNode<G> {
        self
    }
}

impl<G> TreeMethods for PublicArt<G>
where
    G: AffineRepr,
{
    type Node = ArtNode<G>;

    fn root(&self) -> &ArtNode<G> {
        self.tree_root.root()
    }

    fn mut_root(&mut self) -> &mut ArtNode<G> {
        self.tree_root.mut_root()
    }
}

impl<G> TreeMethods for PrivateArt<G>
where
    G: AffineRepr,
{
    type Node = ArtNode<G>;

    fn root(&self) -> &ArtNode<G> {
        self.public_art.tree_root.root()
    }

    fn mut_root(&mut self) -> &mut ArtNode<G> {
        self.public_art.tree_root.mut_root()
    }
}

// impl<G> TreeMethods<G> for PublicZeroArt<G>
// where
//     G: AffineRepr,
// {
//     fn get_root(&self) -> &ArtNode<G> {
//         self.base_art.tree_root.get_root()
//     }
//
//     fn get_mut_root(&mut self) -> &mut ArtNode<G> {
//         self.base_art.tree_root.get_mut_root()
//     }
// }
//
// impl<G, R> TreeMethods<G> for PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn get_root(&self) -> &ArtNode<G> {
//         self.base_art.public_art.tree_root.get_root()
//     }
//
//     fn get_mut_root(&mut self) -> &mut ArtNode<G> {
//         self.base_art.public_art.tree_root.get_mut_root()
//     }
// }
