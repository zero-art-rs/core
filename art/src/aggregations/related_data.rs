use crate::aggregations::{
    AggregationData, EmptyData, ProverAggregationData, VerifierAggregationData,
};
use crate::art::BranchChangesTypeHint;
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

    /// Extend `self` data with `other`. If `replace` is `true`, then replace all the date,
    /// else store them both.
    fn aggregate(&mut self, other: Self);
}

impl<G> RelatedData for ProverAggregationData<G>
where
    G: AffineRepr,
{
    fn aggregate(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.secret_key = other.secret_key;
        self.co_public_key = other.co_public_key;
        self.change_type.extend(other.change_type);
        self.blinding_factor = other.blinding_factor;
    }
}

impl RelatedData for EmptyData {
    fn aggregate(&mut self, _: Self) {}
}

impl<G> RelatedData for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn aggregate(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.co_public_key = other.co_public_key;
        self.change_type.extend(other.change_type);
    }
}

impl<G> RelatedData for AggregationData<G>
where
    G: AffineRepr,
{
    fn aggregate(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.change_type.extend(other.change_type);
    }
}

/// Helper trait requiring public key getter
pub trait HasPublicKey<G> {
    /// Returns public key of the node.
    fn get_public_key(&self) -> G;
}

impl<G> HasPublicKey<G> for ProverAggregationData<G>
where
    G: AffineRepr,
{
    fn get_public_key(&self) -> G {
        self.public_key
    }
}

impl<G> HasPublicKey<G> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn get_public_key(&self) -> G {
        self.public_key
    }
}

pub trait HasChangeTypeHint<G>
where
    G: AffineRepr,
{
    /// Returns Branch change hint.
    fn get_change_type(&self) -> &Vec<BranchChangesTypeHint<G>>;
}

impl<G> HasChangeTypeHint<G> for ProverAggregationData<G>
where
    G: AffineRepr,
{
    fn get_change_type(&self) -> &Vec<BranchChangesTypeHint<G>> {
        &self.change_type
    }
}

impl<G> HasChangeTypeHint<G> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn get_change_type(&self) -> &Vec<BranchChangesTypeHint<G>> {
        &self.change_type
    }
}
