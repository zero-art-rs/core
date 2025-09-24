use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize, Hash)]
pub enum Direction {
    Left,
    Right,
}
