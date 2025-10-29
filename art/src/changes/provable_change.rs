use ark_std::rand::Rng;
use cortado::CortadoAffine;
use zrt_zk::aggregated_art::ProverAggregationTree;
use zrt_zk::art::ArtProof;
use zrt_zk::EligibilityArtefact;
use crate::art::art_types::PrivateZeroArt;
use crate::changes::aggregations::{ChangeAggregation, ProverAggregationData};
use crate::errors::ArtError;
use crate::changes::branch_change::ArtOperationOutput;

pub trait ProvableChange{
    fn prove<'a, R>(
        &self,
        art: &mut PrivateZeroArt<'a, R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    where
        R: Rng + ?Sized,
    ;
}

impl ProvableChange for ArtOperationOutput<CortadoAffine> {
    fn prove<'a, R>(
        &self,
        art: &mut PrivateZeroArt<'a, R>,
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
    fn prove<'a, R>(
        &self,
        art: &mut PrivateZeroArt<'a, R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<ArtProof, ArtError>
    where
        R: Rng + ?Sized,
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => EligibilityArtefact::Member((
                art.get_leaf_secret_key()?,
                art.get_leaf_public_key()?,
            )),
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = art.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok(proof)
    }
}