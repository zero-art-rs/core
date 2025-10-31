use crate::art::art_types::PrivateZeroArt;
use crate::changes::aggregations::{ChangeAggregation, ProverAggregationData};
use crate::changes::branch_change::ArtOperationOutput;
use crate::errors::ArtError;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use zrt_zk::EligibilityArtefact;
use zrt_zk::aggregated_art::ProverAggregationTree;
use zrt_zk::art::ArtProof;

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
///
/// * `R` - a random number generator used during the proof generation process.
pub trait ProvableChange {
    fn prove<R>(
        &self,
        art: &mut PrivateZeroArt<R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    where
        R: Rng + ?Sized;
}

impl ProvableChange for ArtOperationOutput<CortadoAffine> {
    fn prove<R>(
        &self,
        art: &mut PrivateZeroArt<R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    where
        R: Rng + ?Sized,
    {
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => self.eligibility.clone(),
        };

        let context = art.prover_engine.new_context(ad, eligibility);
        let proof = context.prove(&self.artefacts.to_prover_branch(&mut art.rng)?)?;

        Ok(proof)
    }
}

impl ProvableChange for ChangeAggregation<ProverAggregationData<CortadoAffine>> {
    fn prove<R>(
        &self,
        art: &mut PrivateZeroArt<R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    where
        R: Rng + ?Sized,
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => {
                EligibilityArtefact::Owner((art.get_leaf_secret_key()?, art.get_leaf_public_key()?))
            }
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = art.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok(proof)
    }
}
