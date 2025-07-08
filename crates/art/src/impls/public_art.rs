use crate::PublicART;
use crate::{ARTNode, ARTPublicView};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem;

impl<G> ARTPublicView<G> for PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
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

// impl<G> PartialEq for dyn PublicARTView<G>
// where
//     G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
//     G::BaseField: PrimeField,
// {
//     fn eq(&self, other: &Self) -> bool {
//         !(self.get_root().ne(other.get_root()) || self.get_generator() != other.get_generator())
//     }
// }
