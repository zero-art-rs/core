use crate::ARTNode;
use crate::ARTPublicView;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait ARTPrivateView<G>: ARTPublicView<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_secret_key(&self) -> G::ScalarField;
    fn set_secret_key(&mut self, secret_key: &G::ScalarField);
    fn new(root: Box<ARTNode<G>>, generator: G, secret_key: G::ScalarField) -> Self;
}
