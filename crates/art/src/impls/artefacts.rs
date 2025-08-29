use crate::{errors::ARTError, types::ProverArtefacts};
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::cmp::max;

impl<G> ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn try_merge(&mut self, other: &ProverArtefacts<G>) -> Result<(), ARTError> {
        let mut merged_path = Vec::new();
        let mut merged_co_path = Vec::new();
        let mut merged_secrets = Vec::new();

        // Merge path
        for i in 0..max(self.path.len(), other.path.len()) {
            match (self.path.get(i), other.path.get(i)) {
                (Some(a), Some(b)) => merged_path.push(a.add(b).into_affine()),
                (Some(a), None) => merged_path.push(*a),
                (None, Some(b)) => merged_path.push(*b),
                (None, None) => {}
            }
        }

        // Merge secrets
        for i in 0..max(self.path.len(), other.path.len()) {
            match (self.secrets.get(i), other.secrets.get(i)) {
                (Some(a), Some(b)) => merged_secrets.push(a + b),
                (Some(a), None) => merged_secrets.push(*a),
                (None, Some(b)) => merged_secrets.push(*b),
                (None, None) => {}
            }
        }

        // Merge co_path
        for i in 0..max(self.co_path.len(), other.co_path.len()) {
            match (self.co_path.get(i), other.co_path.get(i)) {
                (Some(a), Some(b)) => merged_co_path.push(a.add(b).into_affine()),
                (Some(a), None) => merged_co_path.push(*a),
                (None, Some(b)) => merged_co_path.push(*b),
                (None, None) => {}
            }
        }

        self.path = merged_path;
        self.co_path = merged_co_path;
        self.secrets = merged_secrets;

        Ok(())
    }
}

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
