use crate::errors::ARTError;
use crate::types::{Direction, NodeIndex};
use tracing::error;

impl NodeIndex {
    pub fn as_path(&self) -> Result<Self, ARTError> {
        Ok(Self::Direction(self.get_path()?))
    }

    pub fn as_index(&self) -> Result<Self, ARTError> {
        Ok(Self::Index(self.get_index()?))
    }

    pub fn as_coordinate(&self) -> Result<Self, ARTError> {
        let (level, position) = self.get_coordinate()?;
        Ok(Self::Coordinate(level, position))
    }

    pub fn get_index(&self) -> Result<u64, ARTError> {
        match self {
            NodeIndex::Index(index) => Ok(*index),
            NodeIndex::Coordinate(level, position) => {
                Self::get_index_from_path(&Self::get_path_from_coordinate(*level, *position)?)
            }
            NodeIndex::Direction(path) => Self::get_index_from_path(path),
        }
    }

    pub fn get_coordinate(&self) -> Result<(u64, u64), ARTError> {
        match self {
            NodeIndex::Coordinate(level, position) => Ok((*level, *position)),
            NodeIndex::Index(index) => Self::get_coordinate_from_index(*index),
            NodeIndex::Direction(path) => Self::get_coordinate_from_path(path),
        }
    }

    pub fn get_path(&self) -> Result<Vec<Direction>, ARTError> {
        match self {
            Self::Index(index) => Self::get_path_from_index(*index),
            Self::Coordinate(level, position) => Self::get_path_from_coordinate(*level, *position),
            Self::Direction(direction) => Ok(direction.clone()),
        }
    }

    pub fn get_index_from_path(path: &[Direction]) -> Result<u64, ARTError> {
        let mut index = 1u64;
        for direction in path {
            match direction {
                Direction::Left => index <<= 1,
                Direction::Right => index = (index << 1) + 1,
            }
        }

        Ok(index)
    }

    pub fn is_subpath_of(&self, other: &Self) -> Result<bool, ARTError> {
        let mut is_subpath = true;
        for (a, b) in self.get_path()?.iter().zip(&other.get_path()?) {
            if a != b {
                is_subpath = false;
                break;
            }
        }

        Ok(is_subpath)
    }

    /// Computes the path to the node starting from the root.
    fn get_path_from_index(index: u64) -> Result<Vec<Direction>, ARTError> {
        if index == 0 {
            error!("Failed to convert index: {index} to path");
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

            i >>= 1;
        }

        path.reverse();
        Ok(path)
    }

    /// Computes the path to the node starting from the root.
    fn get_path_from_coordinate(level: u64, position: u64) -> Result<Vec<Direction>, ARTError> {
        if position >= (2 << level) {
            error!(
                "Failed to convert coordinate (l: {level}, p: {position}), as the provided position is to big"
            );
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
                p -= relative_center;
            }

            l -= 1;
        }

        Ok(path)
    }

    fn get_coordinate_from_index(index: u64) -> Result<(u64, u64), ARTError> {
        let mut level = 0u64;
        let mut position = index;

        let mut level_max_width = 1;
        while position > level_max_width {
            position -= level_max_width;
            level_max_width <<= 1;
            level += 1;
        }

        Ok((level, position))
    }

    fn get_coordinate_from_path(path: &Vec<Direction>) -> Result<(u64, u64), ARTError> {
        if path.len() == 0 {
            return Ok((0, 0));
        }

        let mut position = 0u64;

        for next in path {
            match next {
                Direction::Left => position *= 2,
                Direction::Right => position = position * 2 + 1,
            }
        }

        Ok((path.len() as u64, position))
    }

    fn get_intersection(&self, other: &NodeIndex) -> Result<NodeIndex, ARTError> {
        let mut intersection = Vec::new();
        for (a, b) in self.get_path()?.iter().zip(other.get_path()?.iter()) {
            if a == b {
                intersection.push(*a);
            } else {
                return Ok(NodeIndex::Direction(intersection));
            }
        }

        Ok(NodeIndex::Direction(intersection))
    }
}

impl PartialEq<NodeIndex> for NodeIndex {
    fn eq(&self, other: &Self) -> bool {
        match (self.get_path(), other.get_path()) {
            (Ok(index), Ok(other_index)) => index.eq(&other_index),
            _ => false,
        }
    }
}

impl From<u64> for NodeIndex {
    fn from(index: u64) -> Self {
        Self::Index(index)
    }
}

impl From<Vec<Direction>> for NodeIndex {
    fn from(path: Vec<Direction>) -> Self {
        Self::Direction(path)
    }
}

impl From<(u64, u64)> for NodeIndex {
    fn from((level, position): (u64, u64)) -> Self {
        Self::Coordinate(level, position)
    }
}
