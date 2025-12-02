use crate::art::PublicMergeData;
use crate::art_node::{ArtNode, LeafStatus};
use crate::art_node::{ArtNodePreview, BinaryTreeNode};
use crate::helper_tools::prepare_short_marker_for_option;
use crate::node_index::Direction;
use ark_ec::AffineRepr;
use display_tree::{CharSet, DisplayTree, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};

#[derive(DisplayTree)]
pub enum ARTDisplayTree {
    Leaf {
        #[node_label]
        public_key: String,
    },
    Inner {
        #[node_label]
        public_key: String,
        #[tree]
        left: Box<Self>,
        #[tree]
        right: Box<Self>,
    },
}

impl<G> From<&ArtNode<G>> for ARTDisplayTree
where
    G: AffineRepr,
{
    fn from(node: &ArtNode<G>) -> Self {
        let blank_marker = match node {
            ArtNode::Leaf { status, .. } => match status {
                LeafStatus::Active => "Active",
                LeafStatus::PendingRemoval => "PendingRemoval",
                LeafStatus::Blank => "Blank",
            },
            ArtNode::Internal { .. } => "",
        };

        let pk_marker = prepare_short_marker_for_option(&node.public_key().x());

        match node {
            ArtNode::Leaf { .. } => ARTDisplayTree::Leaf {
                public_key: format!(
                    "{} leaf of weight: {}, x: {}",
                    blank_marker,
                    node.weight(),
                    pk_marker,
                ),
            },
            ArtNode::Internal { l, r, .. } => ARTDisplayTree::Inner {
                public_key: format!("Node of weight: {}, x: {}", node.weight(), pk_marker,),
                left: Box::new(ARTDisplayTree::from(l.as_ref())),
                right: Box::new(ARTDisplayTree::from(r.as_ref())),
            },
        }
    }
}

impl<'a, G> From<ArtNodePreview<'a, G>> for AggregationDisplayTree
where
    G: AffineRepr,
{
    fn from(value: ArtNodePreview<'a, G>) -> Self {
        let pk_marker = prepare_short_marker_for_option(&value.public_key().x());

        match (value.child(Direction::Left), value.child(Direction::Right)) {
            (Some(l), Some(r)) => AggregationDisplayTree::BinaryNode {
                public_key: format!("Node {}", pk_marker),
                left: Box::new(l.into()),
                right: Box::new(r.into()),
            },
            (Some(c), None) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {}", Direction::Left, pk_marker),
                child: Box::new(c.into()),
            },
            (None, Some(c)) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {}", Direction::Right, pk_marker),
                child: Box::new(c.into()),
            },
            (None, None) => AggregationDisplayTree::Leaf {
                public_key: format!("Leaf: {}", pk_marker),
            },
        }
    }
}

impl<G> Display for ArtNode<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_tree!(
                ARTDisplayTree::from(self),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::SINGLE_LINE)
            )
        )
    }
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

impl<D> Display for BinaryTreeNode<D>
where
    D: Clone + Display + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_tree!(
                AggregationDisplayTree::from(self),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::SINGLE_LINE)
            )
        )
    }
}

impl<'a, G> Display for ArtNodePreview<'a, G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            format_tree!(
                AggregationDisplayTree::from(self.clone()),
                Style::default()
                    .indentation(4)
                    .char_set(CharSet::SINGLE_LINE)
            )
        )
    }
}

impl Display for LeafStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}

impl<G> Display for PublicMergeData<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let wpk =
            prepare_short_marker_for_option(&self.weak_key.clone().and_then(|point| point.x()));
        let spk =
            prepare_short_marker_for_option(&self.strong_key.clone().and_then(|point| point.x()));
        let op = prepare_short_marker_for_option(&self.status);

        write!(f, "weak_key: {}, strong_key: {}, status: {}", wpk, spk, op)
    }
}

impl<D> From<&Box<BinaryTreeNode<D>>> for AggregationDisplayTree
where
    D: Clone + Display,
{
    fn from(value: &Box<BinaryTreeNode<D>>) -> Self {
        AggregationDisplayTree::from(value.as_ref())
    }
}

impl<D> From<&BinaryTreeNode<D>> for AggregationDisplayTree
where
    D: Display + Clone,
{
    fn from(value: &BinaryTreeNode<D>) -> Self {
        match (value.l.as_ref(), value.r.as_ref()) {
            (Some(l), Some(r)) => AggregationDisplayTree::BinaryNode {
                public_key: format!("Node {}", value.data),
                left: Box::new(l.into()),
                right: Box::new(r.into()),
            },
            (Some(c), None) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {}", Direction::Left, value.data),
                child: Box::new(c.into()),
            },
            (None, Some(c)) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {}", Direction::Right, value.data),
                child: Box::new(c.into()),
            },
            (None, None) => AggregationDisplayTree::Leaf {
                public_key: format!("Leaf: {}", value.data),
            },
        }
    }
}
