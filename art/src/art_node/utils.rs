use ark_ec::AffineRepr;
use crate::art::ArtNodePreview;
use crate::art_node::ArtNode;
use crate::changes::aggregations::AggregationNode;
use crate::node_index::Direction;

pub trait TreeNodeWrapper
where 
    Self: Sized,
{
    fn child(&self, dir: Direction) -> Option<Self>;
}

pub struct PriorityNodePair<T1, T2> {
    main_node: T1,
    secondary_node: Option<T2>,
}

impl<T1, T2> PriorityNodePair<T1, T2> {
    pub fn new(main_node: T1, secondary_node: Option<T2>) -> Self {
        Self {main_node, secondary_node}
    }
    
    pub fn main_node(&self) -> &T1 {
        &self.main_node
    }
    
    pub fn secondary_node(&self) -> Option<&T2> {
        self.secondary_node.as_ref()
    }
}

impl<T1, T2> TreeNodeWrapper for PriorityNodePair<T1, T2>
where 
    T1: TreeNodeWrapper,
    T2: TreeNodeWrapper,
{
    fn child(&self, dir: Direction) -> Option<Self> {
        if let Some(child) = self.main_node.child(dir) {
            let secondary_child = self.secondary_node.as_ref().and_then(|node| node.child(dir));
            return Some(Self::new(child, secondary_child));
        }
        
        None
    }
}

pub struct NodePair<T1, T2> {
    first_node: Option<T1>,
    second_node: Option<T2>,
}

impl<T1, T2> NodePair<T1, T2> {
    pub fn new(main_node: Option<T1>, secondary_node: Option<T2>) -> Option<Self> {
        if main_node.is_none() && secondary_node.is_none() {
            None
        } else {
            Some(Self { first_node: main_node, second_node: secondary_node })
        }
    }

    pub fn with_first_node(main_node: T1, secondary_node: Option<T2>) -> Self {
        Self { first_node: Some(main_node), second_node: secondary_node }
    }
    
    pub fn first_node(&self) -> Option<&T1> {
        self.first_node.as_ref()
    }
    
    pub fn second_node(&self) -> Option<&T2> {
        self.second_node.as_ref()
    }
}

impl<T1, T2> TreeNodeWrapper for NodePair<T1, T2>
where
    T1: TreeNodeWrapper,
    T2: TreeNodeWrapper,
{
    fn child(&self, dir: Direction) -> Option<Self> {
        Self::new(
            self.first_node.as_ref().and_then(|node| node.child(dir)),
            self.second_node.as_ref().and_then(|node| node.child(dir))
        )
    }
}

pub struct AggregationNodeWrapper<'a, D> {
    node: &'a AggregationNode<D>
}

impl<'a, D> AggregationNodeWrapper<'a, D> {
    pub fn new(node: &'a AggregationNode<D>) -> Self {
        Self { node }
    }
    
    pub fn node(&self) -> &AggregationNode<D> {
        &self.node
    }
}

impl<'a, D> TreeNodeWrapper for AggregationNodeWrapper<'a, D> {
    fn child(&self, dir: Direction) -> Option<Self> {
        self.node.child(dir).map(Self::new)
    }
}

impl<'a, G> TreeNodeWrapper for ArtNodePreview<'a, G>
where 
    G: AffineRepr,
{
    fn child(&self, dir: Direction) -> Option<Self> {
        let art_node: Option<&'a ArtNode<G>> = match self.art_node() {
            Some(node) => node.child(dir),
            None => None,
        };

        let merge_node = match self.merge_node() {
            Some(merge_node) => merge_node.child(dir),
            None => None,
        };

        Self::new(art_node, merge_node).ok()
    }
}