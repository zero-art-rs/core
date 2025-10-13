use ark_ec::AffineRepr;
use std::fmt::{Display, Formatter};
use tree_ds::prelude::Tree;

pub type ProverAggregationTree<G> = Tree<u64, AggregatedNodeData<G>>;

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct AggregatedNodeData<G>
where
    G: AffineRepr,
{
    pub public_key: G,
    pub co_public_key: Option<G>,
    pub secret_key: G::ScalarField,
    pub marker: bool,
}

impl<G> Display for AggregatedNodeData<G>
where
    G: AffineRepr,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        let sk_marker = self
            .secret_key
            .to_string()
            .chars()
            .take(8)
            .collect::<String>()
            + "...";

        write!(
            f,
            "pk: {}, co_pk: {}, sk: {}, marker: {}",
            pk_marker, co_pk_marker, sk_marker, self.marker
        )
    }
}
