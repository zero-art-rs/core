use crate::Direction;

pub enum NodeIndex {
    Index(u32),
    Coordinate(u32, u32),
    Direction(Vec<Direction>),
}
