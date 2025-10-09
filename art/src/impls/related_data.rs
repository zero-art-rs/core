use crate::traits::{HasChangeTypeHint, HasPublicKey, RelatedData};
use crate::types::{
    AggregationData, BranchChangesTypeHint, ProverAggregationData, VerifierAggregationData,
};
use ark_ec::AffineRepr;

impl<G> RelatedData for ProverAggregationData<G>
where
    G: AffineRepr,
{
    fn extend(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.secret_key = other.secret_key;
        self.co_public_key = other.co_public_key;
        self.change_type.extend(other.change_type);
        self.latest = other.latest;
    }
}

impl<G> RelatedData for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn extend(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.co_public_key = other.co_public_key;
        self.change_type.extend(other.change_type);
    }
}

impl<G> RelatedData for AggregationData<G>
where
    G: AffineRepr,
{
    fn extend(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.change_type.extend(other.change_type);
    }
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
