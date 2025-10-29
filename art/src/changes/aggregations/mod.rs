//! Module with aggregated changes of the ART.
//!
//! Aggregated changes are different from `BranchChanges` as they can change several branches
//! of the art by one user at the same time.

pub mod aggregated_change;
pub mod aggregated_node;
pub mod aggregation_data;
pub mod related_data;

pub use aggregated_change::{
    ChangeAggregation, ChangeAggregationWithRng, PlainChangeAggregation, ProverChangeAggregation,
};
pub use aggregated_node::{AggregationNode, AggregationNodeIterWithPath};
pub use aggregation_data::{
    AggregationData, EmptyData, ProverAggregationData, VerifierAggregationData,
};
pub use related_data::{HasChangeTypeHint, HasPublicKey, RelatedData};
