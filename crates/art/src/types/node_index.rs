use crate::types::Direction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum NodeIndex {
    /// Sequence number of a node in a tree. The root is 1, his children are 2 and 3, and so on,
    /// down to leaves.
    Index(u32),
    /// Level (starting from root as 0) and position on level (starting from left as 0) of a node
    /// in a tree
    Coordinate(u32, u32),
    /// Path from the root to the node
    Direction(Vec<Direction>),
}
