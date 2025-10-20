use crate::types::{ChangeAggregationNode, Direction};
use ark_ec::AffineRepr;

/// Represents the possible forms of child relationships in a tree.
///
/// The [`Children`] enum supports relations, where the node has two, one or zero children. In
/// comparison with [`FullChildren`] it can have even one child.
///
/// # Type Parameters
/// - `C`: The type of the child nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Children<C>
where
    C: Clone,
{
    Node { l: Box<C>, r: Box<C> },
    Route { c: Box<C>, direction: Direction },
    Leaf,
}

/// Represents the possible forms of child relationships in a tree.
///
/// The [`FullChildren`] enum supports relations, where the node has two or zero children. In
/// comparison with [`Children`] it can't have only one child.
///
/// # Type Parameters
/// - `C`: The type of the child nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FullChildren<C>
where
    C: Clone,
{
    Node { l: Box<C>, r: Box<C> },
    Leaf,
}
