use crate::traits::ChildContainer;
use crate::types::{BinaryChildrenRelation, Direction};

impl<C> ChildContainer<C> for BinaryChildrenRelation<C>
where
    C: Clone + Default,
{
    fn get_child(&self, dir: Direction) -> Option<&C> {
        let child = match dir {
            Direction::Right => self.r.as_ref(),
            Direction::Left => self.l.as_ref(),
        };

        child.map(|r| r.as_ref())
    }

    fn get_mut_child(&mut self, dir: Direction) -> Option<&mut C> {
        let child = match dir {
            Direction::Right => self.r.as_mut(),
            Direction::Left => self.l.as_mut(),
        };

        child.map(|r| r.as_mut())
    }

    fn set_child(&mut self, dir: Direction, node: C) {
        match dir {
            Direction::Left => self.l = Some(Box::new(node)),
            Direction::Right => self.r = Some(Box::new(node)),
        }
    }

    fn is_leaf(&self) -> bool {
        self.r.is_none() && self.l.is_none()
    }

    fn degree(&self) -> usize {
        let mut ctr = 0;

        if self.l.is_some() {
            ctr += 1;
        }
        if self.r.is_some() {
            ctr += 1;
        }

        ctr
    }
}
