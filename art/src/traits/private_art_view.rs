use crate::traits::ARTPublicAPI;
use crate::{
    errors::ARTError,
    traits::ARTPublicView,
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem;

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
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if self.get_node_index().is_subpath_of(other)? {
            return Err(ARTError::InvalidInput);
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // Always update art root key.
        match append_changes {
            true => path_secrets[0] += other_path_secrets[0],
            false => path_secrets[0] = other_path_secrets[0],
        }

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                match append_changes {
                    true => path_secrets[i + 1] += other_path_secrets[i + 1],
                    false => path_secrets[i + 1] = other_path_secrets[i + 1],
                }
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
