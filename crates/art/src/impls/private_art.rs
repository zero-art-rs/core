use crate::{ARTNode, ARTPrivateView, ARTPublicView, PrivateART};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem;

impl<G> ARTPublicView<G> for PrivateART<G>
where
    G: AffineRepr + CanonicalDeserialize + CanonicalSerialize,
    G::BaseField: PrimeField,
{
    fn get_root(&self) -> &Box<ARTNode<G>> {
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

    fn new(root: Box<ARTNode<G>>, generator: G, secret_key: G::ScalarField) -> Self {
        Self {
            root,
            generator,
            secret_key,
        }
    }
}
