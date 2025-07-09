use crate::{errors::ARTError, types::Direction};
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

impl NodeIndex {
    pub fn get_path(&self) -> Result<Vec<Direction>, ARTError> {
        match self {
            Self::Index(index) => Self::get_path_from_index(*index),
            Self::Coordinate(level, position) => Self::get_path_from_coordinate(*level, *position),
            Self::Direction(direction) => Ok(direction.clone()),
        }
    }

    pub fn get_index_from_path(path: &Vec<Direction>) -> Result<u32, ARTError> {
        let mut index = 1u32;
        for direction in path {
            match direction {
                Direction::Left => index = index << 1,
                Direction::Right => index = (index << 1) + 1,
                _ => return Err(ARTError::PathNotExists),
            }
        }

        Ok(index)
    }

    /// Computes the path to the node starting from the root.
    fn get_path_from_index(index: u32) -> Result<Vec<Direction>, ARTError> {
        if index == 0 {
            return Err(ARTError::InvalidInput);
        }

        let mut i = index;

        let mut path = Vec::new();
        while i > 1 {
            if (i & 1) == 0 {
                path.push(Direction::Left);
            } else {
                path.push(Direction::Right);
            }

            i = i >> 1;
        }

        path.reverse();
        Ok(path)
    }

    /// Computes the path to the node starting from the root.
    fn get_path_from_coordinate(level: u32, position: u32) -> Result<Vec<Direction>, ARTError> {
        if position >= (2 << level) {
            return Err(ARTError::InvalidInput);
        }

        let mut path = Vec::new();
        let mut l = level;
        let mut p = position;
        while l != 0 {
            // max number of leaves on level l in a left subtree
            let relative_center = 1 << (l - 1);
            if p < relative_center {
                path.push(Direction::Left);
            } else {
                path.push(Direction::Right);
                p = p - relative_center;
            }

            l -= 1;
        }

        Ok(path)
    }
}
