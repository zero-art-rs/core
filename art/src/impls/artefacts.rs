use crate::errors::ARTError;
use crate::types::{ProverArtefacts, VerifierArtefacts};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::prelude::ThreadRng;
use curve25519_dalek::Scalar;
use zrt_zk::art::{ProverBranchNode, VerifierBranchNode};

impl<G> ProverArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn to_prover_branch(
        &self,
        rng: &mut ThreadRng,
    ) -> Result<Vec<ProverBranchNode<G>>, ARTError> {
        if self.path.len() != self.secrets.len() || self.path.len() != self.co_path.len() + 1 {
            return Err(ARTError::InvalidInput);
        }

        let mut prover_nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            prover_nodes.push(ProverBranchNode::<G> {
                secret: *self.secrets.get(i).ok_or(ARTError::InvalidInput)?,
                // blinding_factor: Scalar::random(rng),
                blinding_factor: G::ScalarField::rand(rng),
                public_key: *self.path.get(i).ok_or(ARTError::InvalidInput)?,
                co_public_key: self.co_path.get(i).map(|g| *g),
            })
        }

        Ok(prover_nodes)
    }
}

impl<G> VerifierArtefacts<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn to_verifier_branch(&self) -> Result<Vec<VerifierBranchNode<G>>, ARTError> {
        if self.path.len() != self.co_path.len() + 1 {
            return Err(ARTError::InvalidInput);
        }

        let mut nodes = Vec::with_capacity(self.path.len());
        for i in 0..self.path.len() {
            nodes.push(VerifierBranchNode::<G> {
                public_key: *self.path.get(i).ok_or(ARTError::InvalidInput)?,
                co_public_key: self.co_path.get(i).map(|g| *g),
            })
        }

        Ok(nodes)
    }
}
