use crate::art::art_node::{ArtNode, NodeIterWithPath};
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::errors::ARTError;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_std::rand::Rng;
use cortado::CortadoAffine;

pub trait TreeMethods<G>
where
    G: AffineRepr,
{
    fn get_root(&self) -> &ArtNode<G>;
    fn get_mut_root(&mut self) -> &mut ArtNode<G>;
    // fn get_child(&self, child: Direction) -> Option<&ArtNode<G>>;
    // fn get_mut_child(&mut self, child: Direction) -> Option<&mut ArtNode<G>>;

    fn get_node(&self, index: &NodeIndex) -> Result<&ArtNode<G>, ARTError> {
        self.get_node_at(&index.get_path()?)
    }

    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ArtNode<G>, ARTError> {
        self.get_mut_node_at(&index.get_path()?)
    }

    fn get_node_at(&self, path: &[Direction]) -> Result<&ArtNode<G>, ARTError> {
        let mut node = self.get_root();
        for direction in path {
            if let Some(child_node) = node.get_child(*direction) {
                node = child_node;
            } else {
                return Err(ARTError::PathNotExists);
            }
        }

        Ok(node)
    }

    fn get_mut_node_at(&mut self, path: &[Direction]) -> Result<&mut ArtNode<G>, ARTError> {
        let mut node = self.get_mut_root();
        for direction in path {
            node = node
                .get_mut_child(*direction)
                .ok_or(ARTError::PathNotExists)?;
        }

        Ok(node)
    }

    // fn get_mut_node(&mut self, index: NodeIndex);
    fn get_leaf_with(&self, public_key: G) -> Result<&ArtNode<G>, ARTError> {
        for (node, _) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(&public_key) {
                return Ok(node);
            }
        }

        Err(ARTError::PathNotExists)
    }

    fn get_path_to_leaf_with(&self, public_key: G) -> Result<Vec<Direction>, ARTError> {
        for (node, path) in NodeIterWithPath::new(self.get_root()) {
            if node.is_leaf() && node.get_public_key().eq(&public_key) {
                return Ok(path
                    .iter()
                    .map(|(_, direction)| *direction)
                    .collect::<Vec<Direction>>());
            }
        }

        Err(ARTError::PathNotExists)
    }

    // fn get_mut_node_with(&mut self, pk: G);
    // fn get_node_at(&self, path: &[Direction]) -> Result<&ArtNode<G>, ARTError>;
    // fn get_mut_node_at(&mut self, path: &[Direction]) -> Result<&mut ArtNode<G>, ARTError>;
    // fn get_child(&self, dir: Direction);
    // fn get_mut_child(&mut self, dir: Direction);
    // fn replace_node(&mut self, target_index: NodeIndex, new_node: ArtNode<G>);
    // fn extend_right(&mut self, target_index: NodeIndex, new_node: ArtNode<G>);
    // fn set_leaf_status(&mut self, target_index: NodeIndex, status: String);
    // ...
}

// pub(crate) trait AdditionalTreeMethods {
//     fn get_node_at(&self, path: Vec<Direction>);
//     fn get_mut_node_at(&mut self, path: Vec<Direction>);
// }

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
