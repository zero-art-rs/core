use crate::art::art_types::{PrivateArt, PrivateZeroArt};
use crate::changes::branch_change::{BranchChange, VerifiableBranchChange};
use crate::errors::ArtError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use zrt_zk::EligibilityArtefact;

pub trait ArtBasicOps<G, R>
where
    G: AffineRepr,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
        eligibility: Option<EligibilityArtefact>,
        ad: &[u8],
    ) -> Result<R, ArtError>;

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility: Option<EligibilityArtefact>,
        ad: &[u8],
    ) -> Result<R, ArtError>;
}

impl<G> ArtBasicOps<G, BranchChange<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
        _: Option<EligibilityArtefact>,
        _: &[u8],
    ) -> Result<BranchChange<G>, ArtError> {
        self.private_update_node_key(target_leaf, new_key, append_changes)
            .map(|(_, change, _)| change)
    }

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        _: Option<EligibilityArtefact>,
        _: &[u8],
    ) -> Result<BranchChange<G>, ArtError> {
        self.private_add_node(new_key).map(|(_, change, _)| change)
    }
}

impl<'a, R> ArtBasicOps<CortadoAffine, VerifiableBranchChange> for PrivateZeroArt<'a, R>
where
    R: ?Sized + Rng,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        append_changes: bool,
        eligibility: Option<EligibilityArtefact>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ArtError> {
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => self.get_member_current_eligibility()?,
        };

        let (_, change, artefacts) =
            self.private_art
                .private_update_node_key(target_leaf, new_key, append_changes)?;

        let prover_context = self.prover_engine.new_context(ad, eligibility);
        let proof = prover_context.prove(&artefacts.to_prover_branch(self.rng)?)?;

        Ok(VerifiableBranchChange {
            branch_change: change,
            proof,
        })
    }

    fn add_node(
        &mut self,
        new_key: Fr,
        eligibility: Option<EligibilityArtefact>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ArtError> {
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => self.get_member_current_eligibility()?,
        };

        let (_, change, artefacts) = self.private_art.private_add_node(new_key)?;

        let prover_context = self.prover_engine.new_context(ad, eligibility);
        let proof = prover_context.prove(&artefacts.to_prover_branch(self.rng)?)?;

        Ok(VerifiableBranchChange {
            branch_change: change,
            proof,
        })
    }
}
