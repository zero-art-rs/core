use std::mem;
use crate::{
    errors::ARTError,
    traits::ARTPublicView,
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use crate::traits::ARTPublicAPI;

pub trait ARTPrivateView<G>: ARTPublicView<G> + ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    /// Returns users secret key
    fn get_secret_key(&self) -> G::ScalarField;

    /// Changes uses secret key to the given one
    fn set_secret_key(&mut self, secret_key: &G::ScalarField);

    /// Returns the path to the users node
    fn get_node_index(&self) -> &NodeIndex;

    /// Changes User node index to the given one
    fn set_node_index(&mut self, node_index: NodeIndex);

    /// Updates users node index by researching it in a tree.
    fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self.get_path_to_leaf(&self.public_key_of(&self.get_secret_key()))?;
        self.set_node_index(NodeIndex::Direction(path).as_index()?);

        Ok(())
    }

    /// Returns new instance of ART
    fn new(
        root: Box<ARTNode<G>>,
        generator: G,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError>;

    /// Returns path secrets: secret keys corresponding to the public key of node o path from
    /// user leaf to root. The first one is users node leaf key, and the last one is the root
    /// secret key.
    fn get_path_secrets(&self) -> &Vec<G::ScalarField>;

    /// Returns mutable set of path secrets.
    fn get_mut_path_secrets(&mut self) -> &mut Vec<G::ScalarField>;

    /// Changes path_secrets to the given ones.
    fn set_path_secrets(&mut self, new_path_secrets: Vec<G::ScalarField>) -> Vec<G::ScalarField>;

    /// If `append_changes` is false, works as set_path_secrets. In the other case, it will
    /// append secrets to available ones. Can be used for make blank to update secrets correctly.
    fn update_path_secrets(
        &mut self,
        other_path_secrets: Vec<G::ScalarField>,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        if append_changes {
            if self.get_path_secrets().len() != other_path_secrets.len() {
                return Err(ARTError::InvalidInput);
            } else {
                for (i, b) in other_path_secrets.iter().enumerate() {
                    self.get_mut_path_secrets()[i] += b;
                }
            }
        } else {
            _ = mem::replace(&mut self.get_path_secrets(), &other_path_secrets);
        }

        Ok(())
    }

    /// Changes path secrets on path from the root to leaf with `other_path_secrets`, using only
    /// those, which are on the path from root to user leaf. Can be used to update path secrets
    /// after applied art changes. On update art, if the other node_index points on the node child,
    /// save old leaf secret and discard one in the changes.
    fn update_path_secrets_with(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if self.get_node_index().is_subpath_of(other)? {
            // Update path after update_key or append_node.
            let node_path = self.get_node_index().get_path()?;
            let other_node_path = other.get_path()?;

            return if node_path.len() == other_node_path.len() {
                self.set_path_secrets(other_path_secrets);
                Ok(())
            } else if node_path.len() + 1 == other_node_path.len() {
                other_path_secrets[0] = path_secrets.pop().ok_or(ARTError::EmptyART)?;
                self.set_path_secrets(other_path_secrets);

                Ok(())
            } else {
                Err(ARTError::InvalidInput)
            };
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Handle case, when the user is the neighbour of the one, who apdated his art
        if node_path.len() == other_node_path.len() {
            let mut node_index_clone = node_path.clone();
            node_index_clone.pop();
            if NodeIndex::Direction(node_index_clone).is_subpath_of(other)? {
                return match self.get_path_secrets().first() {
                    Some(sk) => {
                        other_path_secrets[0] = *sk;
                        self.set_path_secrets(other_path_secrets);
                        Ok(())
                    }
                    None => Err(ARTError::EmptyART),
                }
            }
        }

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // Always update art root key.
        path_secrets[0] = other_path_secrets[0];

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                path_secrets[i + 1] = other_path_secrets[i + 1];
            } else {
                break;
            }
        }

        // Reverse path_secrets back to normal order, and update change old secrets.
        path_secrets.reverse();
        self.set_path_secrets(path_secrets);

        Ok(())
    }

    /// Update path secrets with others. It can be used to merge secrets for conflict change
    /// into art. It checks, which nodes from the `other` change path is different from the path
    /// from user leaf to root. If nodes are the same, then corresponding public keys will be
    /// added together. In other case, those keys will not affect each other.
    fn merge_path_secrets(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        preserve_leaf_key: bool,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if self.get_node_index().is_subpath_of(other)? {
            // Update path after update_key, append_node, or your node removal.
            let node_path = self.get_node_index().get_path()?;
            let other_node_path = other.get_path()?;

            return if node_path.len() == other_node_path.len() {
                self.update_path_secrets(other_path_secrets.clone(), true)?;
                Ok(())
            } else if node_path.len() + 1 == other_node_path.len() {
                if preserve_leaf_key {
                    other_path_secrets[0] = path_secrets.pop().ok_or(ARTError::EmptyART)?;
                }
                for (i, a) in path_secrets.iter().enumerate() {
                    other_path_secrets[i] += a;
                }
                self.set_path_secrets(other_path_secrets.clone());

                Ok(())
            } else {
                Err(ARTError::InvalidInput)
            };
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // Always update art root key.
        path_secrets[0] += other_path_secrets[0];

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                path_secrets[i + 1] += other_path_secrets[i + 1];
            } else {
                break;
            }
        }

        // Reverse path_secrets back to normal order, and update change old secrets.
        path_secrets.reverse();
        self.set_path_secrets(path_secrets);

        Ok(())
    }
}
