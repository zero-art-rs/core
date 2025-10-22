use crate::node_index::Direction;

/// Trait to represent Children type in some tree node.
///
/// The idea is for node to have the field children which implements this trait, and so shift
/// children management from the node implementation.
pub trait TreeNode<C>
where
    C: Clone,
{
    /// Return a reference on a child on the given direction. Return None, if there is no
    /// child there.
    fn get_child(&self, dir: Direction) -> Option<&C>;

    /// Return a mutable reference on a child on the given direction. Return None,
    /// if there is no child there.
    fn get_mut_child(&mut self, dir: Direction) -> Option<&mut C>;

    // /// Set the child on the direction `dir` with the given one. Return mutable reference to
    // /// new child.
    // fn set_child(&mut self, child: Direction, node: C) -> &mut C;

    /// Return true, if the node has no children.
    fn is_leaf(&self) -> bool;

    /// Return a reference of the left child.
    fn get_left(&self) -> Option<&C> {
        self.get_child(Direction::Left)
    }

    /// Return a mutable reference of the left child.
    fn get_mut_left(&mut self) -> Option<&mut C> {
        self.get_mut_child(Direction::Left)
    }

    /// Return a reference of the right child.
    fn get_right(&self) -> Option<&C> {
        self.get_child(Direction::Right)
    }

    /// Return a mutable reference of the right child.
    fn get_mut_right(&mut self) -> Option<&mut C> {
        self.get_mut_child(Direction::Right)
    }

    /// Returns true, if the node has a child on `dir` direction.
    fn has_child(&self, dir: Direction) -> bool {
        self.get_child(dir).is_some()
    }
}
