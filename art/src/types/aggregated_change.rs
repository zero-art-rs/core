use crate::traits::RelatedData;
use crate::types::{
    AggregationData, BinaryChildrenRelation, Direction, ProverAggregationData,
    VerifierAggregationData,
};
use ark_std::rand::Rng;
use display_tree::DisplayTree;

pub type ProverChangeAggregation<'a, G, R> =
    ChangeAggregationWithRng<'a, ProverAggregationData<G>, R>;
pub type PlainChangeAggregation<G> = ChangeAggregation<AggregationData<G>>;
pub type VerifierChangeAggregation<G> = ChangeAggregation<VerifierAggregationData<G>>;

#[derive(Debug, PartialEq, Eq)]
pub struct ChangeAggregationWithRng<'a, D, R>
where
    D: RelatedData + Clone,
    R: Rng + ?Sized,
{
    pub(crate) root: Option<ChangeAggregationNode<D>>,
    pub(crate) rng: &'a mut R,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub(crate) root: Option<ChangeAggregationNode<D>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregationNode<D>
where
    D: RelatedData + Clone,
{
    pub children: BinaryChildrenRelation<Self>,

    pub data: D,
}

#[derive(Debug, Clone)]
pub struct AggregationNodeIterWithPath<'a, D>
where
    D: RelatedData + Clone,
{
    pub current_node: Option<&'a ChangeAggregationNode<D>>,
    pub path: Vec<(&'a ChangeAggregationNode<D>, Direction)>,
}

#[derive(DisplayTree, Debug, Clone)]
pub enum AggregationDisplayTree {
    Leaf {
        #[node_label]
        public_key: String,
    },
    UnaryNode {
        #[node_label]
        public_key: String,
        #[tree]
        child: Box<Self>,
    },
    BinaryNode {
        #[node_label]
        public_key: String,
        #[tree]
        left: Box<Self>,
        #[tree]
        right: Box<Self>,
    },
}
