use crate::traits::RelatedData;
use crate::types::{BranchChangesTypeHint, Children, Direction, ProcessedMarker};
use ark_ec::AffineRepr;
use display_tree::DisplayTree;

#[derive(DisplayTree, Debug, Clone)]
pub enum AggregationDisplayTree {
    Leaf {
        #[node_label]
        public_key: String,
    },
    Route {
        #[node_label]
        public_key: String,
        #[tree]
        child: Box<Self>,
    },
    Node {
        #[node_label]
        public_key: String,
        #[tree]
        left: Box<Self>,
        #[tree]
        right: Box<Self>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProverAggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    pub public_key: G,

    // Public key of the neighbour of the node for every `public_key` except root. For root, if
    // if is empty.
    pub co_public_key: Option<G>,

    /// Secret key of corresponding `public_key`
    pub secret_key: G::ScalarField,

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

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub children: Children<Self>,

    pub data: D,

    pub marker: ProcessedMarker,
}

#[derive(Debug, Clone)]
pub struct AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub current_node: Option<&'a ChangeAggregation<D>>,
    pub path: Vec<(&'a ChangeAggregation<D>, Direction)>,
}

/// Iterator for `ChangesAggregation`, which returns `BranchChanges` in the aggregation.
#[derive(Debug, Clone)]
pub struct BranchChangesIter<'a, D>
where
    D: RelatedData + Clone,
{
    pub inner_iter: AggregationNodeIterWithPath<'a, D>,
}
