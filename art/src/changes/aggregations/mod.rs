//! Module with aggregated changes of the ART.
//!
//! Aggregated changes are different from `BranchChanges` as they can change several branches
//! of the art by one user at the same time.

mod aggregated_change;
mod aggregated_node;
mod aggregation_data;

pub use aggregated_change::{AggregatedChange, AggregationTree};
pub use aggregated_node::{AggregationNode, AggregationNodeIterWithPath};
pub use aggregation_data::{AggregationData, ProverAggregationData, VerifierAggregationData};
