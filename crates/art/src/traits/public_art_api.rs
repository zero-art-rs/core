use crate::{
    errors::ARTError,
    types::{ARTNode, ARTRootKey, BranchChanges, Direction, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;

pub trait ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Returns a co-path to the leaf with a given public key.
    fn get_co_path_values(&self, path: &Vec<Direction>) -> Result<Vec<G>, ARTError>;

    /// Brute-force depth-first search in a tree for a leaf node that matches the given public key. Returns the
    /// path from root to the node.
    fn get_path_to_leaf(&self, user_val: &G) -> Result<Vec<Direction>, ARTError>;

    /// Searches the tree for a leaf node that matches the given public key, and returns the
    /// index of a node. Searching algorithm is depth-first search.
    fn get_leaf_index(&self, user_val: &G) -> Result<u32, ARTError>;

    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<ARTRootKey<G>, ARTError>;

    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError>;

    /// Shorthand for computing public key to given secret.
    fn public_key_of(&self, secret: &G::ScalarField) -> G;

    /// Update all public keys on path from the root to node, corresponding to the given secret
    /// key. Can be used to update art after applied changes.
    fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &Vec<Direction>,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Changes old_secret_key secret key of a leaf to the new_secret_key.
    fn update_key_with_secret_key(
        &mut self,
        old_secret_key: &G::ScalarField,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left-most branch.
    fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, ARTError>;

    /// Extends a leaf on the end of a given path with the given node. This method don't change
    /// other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc.
    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &Vec<Direction>,
    ) -> Result<Direction, ARTError>;

    /// Extends the leaf on a path with new node. New node contains public key corresponding to a
    /// given secret key. Then it updates necessary public keys on a path to root using new
    /// node temporary secret key. Returns new ARTRootKey and BranchChanges for other users.
    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Converts the leaf on a given path to temporary by changing its public key on given temporary
    /// one. This method don't change other art nodes. To update art use update_art_with_secret_key
    /// or update_art_with_changes
    fn make_blank_without_changes(
        &mut self,
        path: &Vec<Direction>,
        temporary_public_key: &G,
    ) -> Result<(), ARTError>;

    /// Converts the leaf on a given path to temporary by changing its public key on given temporary
    /// one. At the end, updates necessary public keys on a path to root. Returns new ARTRootKey
    /// and BranchChanges for other users.
    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Updates art public keys using public keys provided in changes. Can be used after
    /// operations on art like append_node, etc.
    fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Uses public keys provided in changes to change public keys of art.
    /// Those public keys are located on a path from root to node, corresponding to user, which
    /// provided changes.
    fn update_art_with_changes_and_path(
        &mut self,
        changes: &BranchChanges<G>,
        path: &Vec<Direction>,
    ) -> Result<(), ARTError>;

    /// Returns mutable node by the given path to it
    fn get_node_by_path(&mut self, next: &Vec<Direction>) -> Result<&mut ARTNode<G>, ARTError>;

    /// Returns mutable node by the given coordinate of a node. For example, the root is (l:0, p:0),
    /// while its childrens are (l: 1, p: 0) and l: 1, p: 1).
    fn get_node_by_coordinate(
        &mut self,
        level: u32,
        position: u32,
    ) -> Result<&mut ARTNode<G>, ARTError>;

    /// Returns mutable node by the given index of a node. For example, root have index 0, its
    /// children are 1 and 2.
    fn get_node_by_index(&mut self, index: u32) -> Result<&mut ARTNode<G>, ARTError>;

    /// Returns mutable node by the given ARTNodeIndex
    fn get_node(&mut self, index: NodeIndex) -> Result<&mut ARTNode<G>, ARTError>;

    /// This check says if the node can be immediately removed from a tree. Those cases are
    /// specific, so in general don't remove nodes and make them temporary instead
    fn can_remove(&mut self, lambda: &G::ScalarField, public_key: &G) -> bool;

    /// Remove the last node in the given path if can
    fn remove_node(&mut self, path: &Vec<Direction>) -> Result<(), ARTError>;

    /// Remove the last node in the given path if can and update public keys on a path from root to
    /// leaf
    fn remove_node_and_update_tree(
        &mut self,
        lambda: &G::ScalarField,
        public_key: &G,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    fn min_max_leaf_height(&self) -> Result<(u32, u32), ARTError>;

    fn get_disbalance(&self) -> Result<u32, ARTError>;

    /// Updates art with given changes.
    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;
}
