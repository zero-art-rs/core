use crate::traits::ChildContainer;
use crate::types::{Children, Direction, FullChildren};
use std::mem;

impl<C> ChildContainer<C> for Children<C>
where
    C: Clone + Default,
{
    fn get_child(&self, child: Direction) -> Option<&C> {
        match self {
            Self::Leaf => None,
            Self::Node { l, r } => match child {
                Direction::Right => Some(r),
                Direction::Left => Some(l),
            },
            Self::Route { c, direction } => {
                if child.eq(direction) {
                    Some(c)
                } else {
                    None
                }
            }
        }
    }

    fn get_mut_child(&mut self, child: Direction) -> Option<&mut C> {
        match self {
            Self::Leaf => None,
            Self::Node { l, r } => match child {
                Direction::Right => Some(r),
                Direction::Left => Some(l),
            },
            Self::Route { c, direction } => {
                if child.eq(direction) {
                    Some(c)
                } else {
                    None
                }
            }
        }
    }

    fn set_child(&mut self, child: Direction, node: C) {
        match self {
            Self::Leaf => {
                *self = Self::Route {
                    c: Box::new(node),
                    direction: child,
                }
            }
            Self::Node { l, r } => match child {
                Direction::Right => *r = Box::new(node),
                Direction::Left => *l = Box::new(node),
            },
            Self::Route { c, direction } => {
                if child.eq(direction) {
                    *c = Box::new(node);
                } else {
                    let taken_c = mem::replace(c, Box::new(C::default()));

                    match direction {
                        Direction::Right => {
                            *self = Self::Node {
                                l: Box::new(node),
                                r: taken_c,
                            }
                        }
                        Direction::Left => {
                            *self = Self::Node {
                                r: Box::new(node),
                                l: taken_c,
                            }
                        }
                    }
                }
            }
        }
    }

    fn is_leaf(&self) -> bool {
        if let Self::Leaf = &self { true } else { false }
    }
}

impl<C> ChildContainer<C> for FullChildren<C>
where
    C: Clone + Default,
{
    fn get_child(&self, child: Direction) -> Option<&C> {
        match self {
            Self::Leaf => None,
            Self::Node { l, r } => match child {
                Direction::Right => Some(r),
                Direction::Left => Some(l),
            },
        }
    }

    fn get_mut_child(&mut self, child: Direction) -> Option<&mut C> {
        match self {
            Self::Leaf => None,
            Self::Node { l, r } => match child {
                Direction::Right => Some(r),
                Direction::Left => Some(l),
            },
        }
    }

    fn set_child(&mut self, child: Direction, node: C) {
        match self {
            Self::Leaf => {
                *self = Self::Node {
                    l: Box::new(node),
                    r: Box::new(C::default()),
                }
            }
            Self::Node { l, r } => match child {
                Direction::Right => *r = Box::new(node),
                Direction::Left => *l = Box::new(node),
            },
        }
    }

    fn is_leaf(&self) -> bool {
        if let Self::Leaf = &self { true } else { false }
    }
}

impl<C> Default for Children<C>
where
    C: Clone,
{
    fn default() -> Self {
        Self::Leaf
    }
}

impl<C> Default for FullChildren<C>
where
    C: Clone,
{
    fn default() -> Self {
        Self::Leaf
    }
}
