use std::mem;

/// This is a trait used to represent the data stored in the node.
///
/// The idea behind this trait is to make node more usable, in a way, it can store different data.
pub trait RelatedData
where
    Self: Sized,
{
    /// Replace the data with the provided `other` one. Return old data.
    fn replace(&mut self, other: Self) -> Self {
        mem::replace(self, other)
    }
}
