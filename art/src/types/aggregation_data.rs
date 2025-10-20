use crate::types::BranchChangesTypeHint;
use ark_ec::AffineRepr;
use curve25519_dalek::Scalar;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProverAggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    pub public_key: G,

    // Public key of the neighbour of the node for every `public_key` except root. For root, if
    // it is empty.
    pub co_public_key: Option<G>,

    /// Secret key of corresponding `public_key`
    pub secret_key: G::ScalarField,

    /// Blinding value for proof creation.
    pub blinding_factor: Scalar,

    /// Change type marker
    pub change_type: Vec<BranchChangesTypeHint<G>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    pub public_key: G,

    /// Change type marker
    pub change_type: Vec<BranchChangesTypeHint<G>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EmptyData {}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifierAggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    pub public_key: G,

    // Public key of the neighbour of the node for every `public_key` except root. For root, if is empty.
    pub co_public_key: Option<G>,

    /// Change type marker
    pub change_type: Vec<BranchChangesTypeHint<G>>,
}
