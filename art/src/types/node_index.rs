use crate::types::Direction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Eq)]
pub enum NodeIndex {
    /// Sequence number of a node in a tree. The root is 1, his children are 2 and 3, and so on,
    /// down to leaves.
    Index(u64),
    /// Level (starting from root as 0) and position on level (starting from left as 0) of a node
    /// in a tree
    Coordinate(u64, u64),
    /// Path from the root to the node
    Direction(Vec<Direction>),
}

#[cfg(test)]
mod tests {
    use crate::types::{Direction, NodeIndex};

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
}
