//! Module with structures used to point on some node of the tree.

use crate::errors::ArtError;
use serde::{Deserialize, Serialize};
use tracing::error;

/// Possible identifier of a child node in binary tree.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Hash)]
pub enum Direction {
    Left,
    Right,
}

impl Direction {
    /// Returns the opposite direction to `self`.
    pub fn other(&self) -> Self {
        match self {
            Direction::Left => Direction::Right,
            Direction::Right => Direction::Left,
        }
    }
}

/// A structure that identifies a node by its position relative to the root.
#[derive(Debug, Clone, Deserialize, Serialize, Eq)]
pub enum NodeIndex {
    /// Sequence number of a node in a tree. The root is 1, his children are 2 and 3, and so on,
    /// down to leaves. Binary representation of the index, also denotes the direction, where the
    /// node is located. If the bit is 0, then go left, else go right.
    Index(u64),
    /// Level (starting from root as 0) and position on level (starting from left as 0) of a node
    /// in a tree.
    Coordinate(u64, u64),
    /// Path from the root to the node.
    Direction(Vec<Direction>),
}

impl Default for NodeIndex {
    fn default() -> Self {
        NodeIndex::Index(1)
    }
}

impl NodeIndex {
    pub fn as_path(&self) -> Result<Self, ArtError> {
        Ok(Self::Direction(self.get_path()?))
    }

    pub fn as_index(&self) -> Result<Self, ArtError> {
        Ok(Self::Index(self.get_index()?))
    }

    pub fn as_coordinate(&self) -> Result<Self, ArtError> {
        let (level, position) = self.get_coordinate()?;
        Ok(Self::Coordinate(level, position))
    }

    pub fn get_index(&self) -> Result<u64, ArtError> {
        match self {
            NodeIndex::Index(index) => Ok(*index),
            NodeIndex::Coordinate(level, position) => {
                Self::get_index_from_path(&Self::get_path_from_coordinate(*level, *position)?)
            }
            NodeIndex::Direction(path) => Self::get_index_from_path(path),
        }
    }

    pub fn get_coordinate(&self) -> Result<(u64, u64), ArtError> {
        match self {
            NodeIndex::Coordinate(level, position) => Ok((*level, *position)),
            NodeIndex::Index(index) => Self::get_coordinate_from_index(*index),
            NodeIndex::Direction(path) => Self::get_coordinate_from_path(path),
        }
    }

    pub fn get_path(&self) -> Result<Vec<Direction>, ArtError> {
        match self {
            Self::Index(index) => Self::get_path_from_index(*index),
            Self::Coordinate(level, position) => Self::get_path_from_coordinate(*level, *position),
            Self::Direction(direction) => Ok(direction.clone()),
        }
    }

    pub fn get_index_from_path(path: &[Direction]) -> Result<u64, ArtError> {
        let mut index = 1u64;
        for direction in path {
            match direction {
                Direction::Left => index <<= 1,
                Direction::Right => index = (index << 1) + 1,
            }
        }

        Ok(index)
    }

    pub fn is_subpath_of(&self, other: &Self) -> Result<bool, ArtError> {
        self.is_subpath_of_vec(&other.get_path()?)
    }

    pub fn is_subpath_of_vec(&self, other: &[Direction]) -> Result<bool, ArtError> {
        let mut is_subpath = true;
        for (a, b) in self.get_path()?.iter().zip(other) {
            if a != b {
                is_subpath = false;
                break;
            }
        }

        Ok(is_subpath)
    }

    /// Adds direction to the path. New index will point on left of right child of the
    /// previous one.
    pub fn push(&mut self, dir: Direction) {
        match self {
            NodeIndex::Index(index) => match dir {
                Direction::Left => *index <<= 1,
                Direction::Right => *index = (*index << 1) + 1,
            },
            NodeIndex::Coordinate(level, position) => {
                *level += 1;
                match dir {
                    Direction::Left => *position <<= 1,
                    Direction::Right => *position = (*position << 1) + 1,
                }
            }
            NodeIndex::Direction(path) => path.push(dir),
        }
    }

    /// Returns an intersection with the other index, i.e. the path from root to the lowest common
    /// node on both paths
    pub fn intersect_with(&self, other: &NodeIndex) -> Result<Vec<Direction>, ArtError> {
        let mut intersection: Vec<Direction> = vec![];
        for (a, b) in self.get_path()?.iter().zip(&other.get_path()?) {
            if a == b {
                intersection.push(*a);
            } else {
                return Ok(intersection);
            }
        }

        Ok(intersection)
    }

    /// Computes the path to the node starting from the root.
    fn get_path_from_index(index: u64) -> Result<Vec<Direction>, ArtError> {
        if index == 0 {
            error!("Failed to convert index: {index} to path");
            return Err(ArtError::InvalidInput);
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
    fn get_path_from_coordinate(level: u64, position: u64) -> Result<Vec<Direction>, ArtError> {
        if position >= (2 << level) {
            error!(
                "Failed to convert coordinate (l: {level}, p: {position}), as the provided position is to big"
            );
            return Err(ArtError::InvalidInput);
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

    fn get_coordinate_from_index(index: u64) -> Result<(u64, u64), ArtError> {
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

    fn get_coordinate_from_path(path: &Vec<Direction>) -> Result<(u64, u64), ArtError> {
        if path.is_empty() {
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

#[cfg(test)]
mod tests {
    use super::{Direction, NodeIndex};
    use crate::art::PrivateArt;
    use crate::art_node::TreeMethods;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use std::ops::Mul;

    #[test]
    fn test_path_to_index_conversion() {
        assert_eq!(
            NodeIndex::Direction(vec![]).get_index().unwrap(),
            1,
            "index from path to root is 1"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Left])
                .get_index()
                .unwrap(),
            2,
            "index from path to root is 2"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Right])
                .get_index()
                .unwrap(),
            3,
            "index from path to root is 3"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Left, Direction::Left])
                .get_index()
                .unwrap(),
            4,
            "index from path to root is 4"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Left, Direction::Right])
                .get_index()
                .unwrap(),
            5,
            "index from path to root is 5"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Right, Direction::Left])
                .get_index()
                .unwrap(),
            6,
            "index from path to root is 6"
        );

        assert_eq!(
            NodeIndex::Direction(vec![Direction::Right, Direction::Right])
                .get_index()
                .unwrap(),
            7,
            "index from path to root is 7"
        );
    }

    #[test]
    fn test_index_to_path_conversion() {
        assert_eq!(
            Vec::<Direction>::new(),
            NodeIndex::Index(1).get_path().unwrap(),
            "index from path to root is 1"
        );

        assert_eq!(
            vec![Direction::Left],
            NodeIndex::Index(2).get_path().unwrap(),
            "index from path to root is 2"
        );

        assert_eq!(
            vec![Direction::Right],
            NodeIndex::Index(3).get_path().unwrap(),
            "index from path to root is 3"
        );

        assert_eq!(
            vec![Direction::Left, Direction::Left],
            NodeIndex::Index(4).get_path().unwrap(),
            "index from path to root is 4"
        );

        assert_eq!(
            vec![Direction::Left, Direction::Right],
            NodeIndex::Index(5).get_path().unwrap(),
            "index from path to root is 4"
        );

        assert_eq!(
            vec![Direction::Right, Direction::Left],
            NodeIndex::Index(6).get_path().unwrap(),
            "index from path to root is 4"
        );

        assert_eq!(
            vec![Direction::Right, Direction::Right],
            NodeIndex::Index(7).get_path().unwrap(),
            "index from path to root is 4"
        );
    }

    #[test]
    fn test_correctness_of_coordinate_enumeration_in_art() {
        let number_of_users = 32;

        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..number_of_users)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let tree = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let node_pk = tree
            .node(&NodeIndex::Coordinate(0, 0))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree.root().data().public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(1, 0))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .child(Direction::Left)
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(1, 1))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .child(Direction::Right)
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(4, 0))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .node_at(&[
                Direction::Left,
                Direction::Left,
                Direction::Left,
                Direction::Left,
            ])
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(4, 11))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .node_at(&[
                Direction::Right,
                Direction::Left,
                Direction::Right,
                Direction::Right,
            ])
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(4, 15))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .node_at(&[
                Direction::Right,
                Direction::Right,
                Direction::Right,
                Direction::Right,
            ])
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Coordinate(5, 31))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .node_at(&[
                Direction::Right,
                Direction::Right,
                Direction::Right,
                Direction::Right,
                Direction::Right,
            ])
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));
    }

    #[test]
    fn test_art_node_index_enumeration() {
        let number_of_users = 32;

        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..number_of_users)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut tree = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Index(1))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree.root().data().public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Index(2))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .child(Direction::Left)
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Index(3))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .child(Direction::Right)
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .public_art()
            .node(&NodeIndex::Index(27))
            .unwrap()
            .data()
            .public_key();
        let root_pk = tree
            .root()
            .node_at(&[
                Direction::Right,
                Direction::Left,
                Direction::Right,
                Direction::Right,
            ])
            .unwrap()
            .data()
            .public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = CortadoAffine::generator().mul(&secrets[2]).into_affine();
        let node_index = NodeIndex::get_index_from_path(
            &tree.public_art().root().path_to_leaf_with(node_pk).unwrap(),
        )
        .unwrap();
        let rec_node_pk = tree
            .public_art()
            .node(&NodeIndex::Index(node_index))
            .unwrap()
            .data()
            .public_key();
        assert!(node_pk.eq(&rec_node_pk));
    }
}
