use crate::{
    errors::ARTError,
    traits::{ARTPublicAPI, ARTPublicView},
    types::{ARTNode, Direction, NodeIndex},
};
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
    fn get_node_index(&self) -> &NodeIndex;
    fn set_node_index(&mut self, node_index: NodeIndex);

    fn update_node_index(&mut self) -> Result<(), ARTError>;

    fn new(
        root: Box<ARTNode<G>>,
        generator: G,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError>;
}
