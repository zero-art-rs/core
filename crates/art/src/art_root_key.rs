use crate::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(bound = "")]
pub struct ARTRootKey<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub key: G::ScalarField,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
}
