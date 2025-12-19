use crate::art::PublicMergeData;
use crate::art_node::{ArtNode, ArtNodeData, LeafStatus};
use crate::art_node::{ArtNodePreview, BinaryTreeNode};
use crate::helper_tools::prepare_short_marker_for_option;
use crate::node_index::Direction;
use ark_ec::AffineRepr;
use display_tree::{CharSet, DisplayTree, Style, StyleBuilder, format_tree};
use std::fmt::{Display, Formatter};
use serde_json::to_string;
use tracing_subscriber::fmt::format;

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

impl<'a, G> From<ArtNodePreview<'a, G>> for AggregationDisplayTree
where
    G: AffineRepr,
{
    fn from(value: ArtNodePreview<'a, G>) -> Self {
        let pk_marker = prepare_short_marker_for_option(&value.public_key().x());
        let status = value
            .status()
            .map(|s| format!("{:?}", s))
            .unwrap_or("None".to_string());

        match (value.child(Direction::Left), value.child(Direction::Right)) {
            (Some(l), Some(r)) => AggregationDisplayTree::BinaryNode {
                public_key: format!("Node {{ pk_marker={pk_marker}, status={status} }}"),
                left: Box::new(l.into()),
                right: Box::new(r.into()),
            },
            (Some(c), None) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {{ pk_marker={pk_marker}, status={status} }}", Direction::Left),
                child: Box::new(c.into()),
            },
            (None, Some(c)) => AggregationDisplayTree::UnaryNode {
                public_key: format!("{:?}: {{ pk_marker={pk_marker}, status={status} }}", Direction::Right),
                child: Box::new(c.into()),
            },
            (None, None) => AggregationDisplayTree::Leaf {
                public_key: format!("Leaf: {{ pk_marker={pk_marker}, status={status} }}"),
            },
        }
    }
}

impl<G: AffineRepr> Display for ArtNodeData<G> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker =
            prepare_short_marker_for_option(&self.public_key().x());

        match self {
            ArtNodeData::Leaf { status, metadata, .. } => {
                write!(f, "Leaf {{public_key: ({pk_marker}, _), status: {status:?}, metadata: {metadata:?}}}", )
            }
            ArtNodeData::Internal { weight, .. } => {
                write!(f, "Internal {{public_key: ({pk_marker}..., _), weight: {weight}}}", )
            }
        }
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
    D: Clone + Display,
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
