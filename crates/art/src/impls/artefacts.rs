use crate::types::ProverArtefacts;
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

impl<G> Default for ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    fn default() -> Self {
        Self {
            path: Vec::new(),
            secrets: Vec::new(),
            co_path: Vec::new(),
        }
    }
}
