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
    /// Returns the root of the ART.
    fn get_root(&self) -> &ARTNode<G>;
    
    /// Returns the mutable root of the ART.
    fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>>;
    
    /// Returns generator used in ART.
    fn get_generator(&self) -> G;

    /// changes the root of the art with the given one. Returns teh old root.
    fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>>;
}
