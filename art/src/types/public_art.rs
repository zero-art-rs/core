use crate::{
    helper_tools::{ark_de, ark_se},
    types::ARTNode,
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
#[serde(bound = "")]
pub struct PublicART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}
