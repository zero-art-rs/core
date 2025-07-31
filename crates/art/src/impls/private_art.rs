use crate::{
    errors::ARTError,
    traits::{ARTPrivateView, ARTPublicAPI, ARTPublicView},
    types::{ARTNode, NodeIndex, PrivateART, PublicART},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem;

impl<G> ARTPublicView<G> for PrivateART<G>
where
    G: AffineRepr + CanonicalDeserialize + CanonicalSerialize,
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

impl<G> ARTPrivateView<G> for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_secret_key(&self) -> G::ScalarField {
        self.secret_key
    }
    fn set_secret_key(&mut self, secret_key: &G::ScalarField) {
        self.secret_key = secret_key.clone();
    }

    fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    fn set_node_index(&mut self, node_index: NodeIndex) {
        self.node_index = node_index
    }

    fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self.get_path_to_leaf(&self.public_key_of(&self.get_secret_key()))?;
        self.set_node_index(NodeIndex::Direction(path));

        Ok(())
    }

    fn new(
        root: Box<ARTNode<G>>,
        generator: G,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError> {
        let public_art = PublicART { root, generator };

        Self::from_public_art(public_art, secret_key)
    }
}
