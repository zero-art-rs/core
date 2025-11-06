use ark_std::rand::Rng;
use tracing::trace;
use crate::changes::branch_change::PrivateBranchChange;
use crate::errors::ArtError;
use cortado::CortadoAffine;
use zrt_zk::aggregated_art::ProverAggregationTree;
use zrt_zk::EligibilityArtefact;
use zrt_zk::art::ArtProof;
use crate::art::{AggregationContext, PrivateZeroArt};
use crate::art::art_types::PrivateArt;

/// A trait for structures that can be proved.
///
/// This trait can be used for output of ART update to proof your ability to update it. The
/// proof generation depends on:
///   * `art` - The state of the art and random number generator stored exclusively (for now) in PrivateZeroArt.
///   * `ad` - the associated auxiliary data supplied by the caller
///   * `eligibility` - the optional eligibility artefact. If None, then the default one will be used if possible.
///
/// If proof generation succeeds, an `ArtProof` is returned, else an `ArtError`.
///
/// # Type Parameters
pub trait ProvableChange {
    fn prove(
        &self,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>;
}

impl ProvableChange for PrivateBranchChange<CortadoAffine> {
    fn prove(
        &self,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    {
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => self.eligibility.clone(),
        };

        trace!("prover_branch: {:#?}", self.prover_branch);
        trace!("eligibility: {:#?}", eligibility);

        let context = self.prover_engine.new_context(ad, eligibility);
        let proof = context.prove(&self.prover_branch)?;

        Ok(proof)
    }
}

impl<R> ProvableChange for AggregationContext<PrivateArt<CortadoAffine>, CortadoAffine, R>
where
    R: Rng + ?Sized
{
    fn prove(&self, ad: &[u8], eligibility: Option<EligibilityArtefact>) -> Result<ArtProof, ArtError>
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => {
                EligibilityArtefact::Owner((
                    self.operation_tree.get_leaf_secret_key(),
                    self.operation_tree.get_leaf_public_key())
                )
            }
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = self.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok(proof)
    }
}

impl<R> ProvableChange for AggregationContext<PrivateZeroArt<CortadoAffine, R>, CortadoAffine, R>
where
    R: Rng + ?Sized
{
    fn prove(&self, ad: &[u8], eligibility: Option<EligibilityArtefact>) -> Result<ArtProof, ArtError>
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => {
                EligibilityArtefact::Owner((
                    self.operation_tree.get_upstream_art().get_leaf_secret_key(),
                    self.operation_tree.get_upstream_art().get_leaf_public_key())
                )
            }
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = self.operation_tree.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok(proof)
    }
}
