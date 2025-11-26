// use crate::art::{PrivateZeroArt, PublicZeroArt};
use crate::changes::aggregations::AggregatedChange;
use crate::changes::branch_change::BranchChange;
use crate::errors::ArtError;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use zrt_zk::EligibilityRequirement;
use zrt_zk::aggregated_art::VerifierAggregationTree;
use zrt_zk::art::ArtProof;

/// Describes an ART change, which can be verified.
///
/// Verification requires the next input:
/// - `art` - the current of the ART
/// - `ad` - the associated auxiliary data used in proof
/// - `eligibility_requirement` - an eligibility requirement defining the update right of the proof creator
/// - `proof` - proof which will be verified
pub trait VerifiableChange<T> {
    /// Fail if proof is invalid. Else returns `Ok(())`.
    fn verify(
        &self,
        art: &T,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError>;
}

// impl VerifiableChange<PublicZeroArt<CortadoAffine>> for BranchChange<CortadoAffine> {
//     fn verify(
//         &self,
//         art: &PublicZeroArt<CortadoAffine>,
//         ad: &[u8],
//         eligibility_requirement: EligibilityRequirement,
//         proof: &ArtProof,
//     ) -> Result<(), ArtError> {
//         let verification_branch = art
//             .base_art
//             .compute_artefacts_for_verification(self)?
//             .to_verifier_branch()?;
//
//         let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
//         verifier_context.verify(proof, &verification_branch)?;
//
//         Ok(())
//     }
// }
//
// impl<R> VerifiableChange<PrivateZeroArt<CortadoAffine, R>> for BranchChange<CortadoAffine>
// where
//     R: Rng + ?Sized,
// {
//     fn verify(
//         &self,
//         art: &PrivateZeroArt<CortadoAffine, R>,
//         ad: &[u8],
//         eligibility_requirement: EligibilityRequirement,
//         proof: &ArtProof,
//     ) -> Result<(), ArtError> {
//         let verification_branch = art
//             .base_art
//             .get_public_art()
//             .compute_artefacts_for_verification(self)?
//             .to_verifier_branch()?;
//
//         let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
//         verifier_context.verify(proof, &verification_branch)?;
//
//         Ok(())
//     }
// }
//
// impl VerifiableChange<PublicZeroArt<CortadoAffine>> for AggregatedChange<CortadoAffine> {
//     fn verify(
//         &self,
//         art: &PublicZeroArt<CortadoAffine>,
//         ad: &[u8],
//         eligibility_requirement: EligibilityRequirement,
//         proof: &ArtProof,
//     ) -> Result<(), ArtError> {
//         let extracted_agg = self.add_co_path(&art.base_art)?;
//         let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;
//
//         let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
//         verifier_context.verify_aggregated(&verifier_tree, proof)?;
//
//         Ok(())
//     }
// }
//
// impl<R> VerifiableChange<PrivateZeroArt<CortadoAffine, R>> for AggregatedChange<CortadoAffine>
// where
//     R: Rng + ?Sized,
// {
//     fn verify(
//         &self,
//         art: &PrivateZeroArt<CortadoAffine, R>,
//         ad: &[u8],
//         eligibility_requirement: EligibilityRequirement,
//         proof: &ArtProof,
//     ) -> Result<(), ArtError> {
//         let extracted_agg = self.add_co_path(&art.base_art.public_art)?;
//         let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;
//
//         let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
//         verifier_context.verify_aggregated(&verifier_tree, proof)?;
//
//         Ok(())
//     }
// }
