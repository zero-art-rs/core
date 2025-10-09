use crate::types::BranchChangesTypeHint;
use ark_ec::AffineRepr;
use std::mem;

/// This is a trait used to represent the data stored in the node.
///
/// The idea behind this trait is to make node more usable, in a way, it can store different data.
pub trait RelatedData
where
    Self: Sized,
{
    /// Replace the data with the provided `other` one. Return old data.
    fn replace(&mut self, other: Self) -> Self {
        mem::replace(self, other)
    }

    /// Extend `self` data with `other`.
    fn extend(&mut self, other: Self);
}

/// Helper trait requiring public key getter
pub trait HasPublicKey<G> {
    /// Returns public key of the node.
    fn get_public_key(&self) -> G;
}

pub trait HasChangeTypeHint<G>
where
    G: AffineRepr,
{
    /// Returns Branch change hint.
    fn get_change_type(&self) -> &Vec<BranchChangesTypeHint<G>>;
}
