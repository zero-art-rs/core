use crate::types::ARTNode;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait ARTPublicView<G>
where
    Self: Sized + Clone,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_root(&self) -> &ARTNode<G>;
    fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>>;
    fn get_generator(&self) -> G;

    /// changes the root node with the given one. Old root node is returned.
    fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>>;
}
