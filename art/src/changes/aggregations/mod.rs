//! Module with aggregated changes of the ART.
//!
//! Aggregated changes are different from `BranchChanges` as they can change several branches
//! of the art by one user at the same time.

mod aggregated_change;
mod aggregated_node;
mod aggregation_data;

pub use aggregated_change::{AggregatedChange, BinaryTree, PrivateAggregatedChange};
pub use aggregated_node::{
    AggregationNodeIterWithPath, BinaryTreeNode, BinaryTreeNodeWrapper, TreeNodeIterWithPath,
};
pub use aggregation_data::{AggregationData, ProverAggregationData, VerifierAggregationData};
