use crate::traits::ARTPublicAPI;
use crate::{
    traits::ARTPublicView,
    types::NodeIndex,
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

    /// Returns path secrets: secret keys corresponding to the public key of node o path from
    /// user leaf to root. The first one is users node leaf key, and the last one is the root
    /// secret key.
    fn get_path_secrets(&self) -> &Vec<G::ScalarField>;

    /// Returns mutable set of path secrets.
    fn get_mut_path_secrets(&mut self) -> &mut Vec<G::ScalarField>;

    /// Changes path_secrets to the given ones.
    fn set_path_secrets(&mut self, new_path_secrets: Vec<G::ScalarField>) -> Vec<G::ScalarField> {
        mem::replace(self.get_mut_path_secrets(), new_path_secrets)
    }
}
