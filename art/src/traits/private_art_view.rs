use crate::{
    errors::ARTError,
    traits::ARTPublicView,
    types::{ARTNode, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait ARTPrivateView<G>: ARTPublicView<G>
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
    fn update_node_index(&mut self) -> Result<(), ARTError>;

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
        new_path_secrets: Vec<G::ScalarField>,
        append_changes: bool,
    ) -> Result<(), ARTError>;

    /// Changes path secrets on path from the root to leaf with `other_path_secrets`, using only
    /// those, which are on the path from root to user leaf. Can be used to update path secrets
    /// after applied art changes. On update art, if the other node_index points on the node child,
    /// save old leaf secret and discard one in the changes.
    fn update_path_secrets_with(
        &mut self,
        other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
    ) -> Result<(), ARTError>;

    /// Update path secrets with others. It can be used to merge secrets for conflict change
    /// into art. It checks, which nodes from the `other` change path is different from the path
    /// from user leaf to root. If nodes are the same, then corresponding public keys will be
    /// added together. In other case, those keys will not affect each other.
    fn merge_path_secrets(
        &mut self,
        other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        preserve_leaf_key: bool,
    ) -> Result<(), ARTError>;
}
