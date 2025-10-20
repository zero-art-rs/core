use crate::types::{ChangeAggregationNode, Direction};
use ark_ec::AffineRepr;

/// Represents the possible forms of child relationships in a tree.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BinaryChildrenRelation<C>
where
    C: Clone,
{
    pub l: Option<Box<C>>,
    pub r: Option<Box<C>>,
}
