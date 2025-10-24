use crate::art::EligibilityProofInput;
use crate::art::art_types::{PrivateArt, PrivateZeroArt};
use crate::art::branch_change::{BranchChange, VerifiableBranchChange};
use crate::errors::ARTError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use zrt_zk::art::art_prove;

pub trait ArtBasicOps<G, R>
where
    G: AffineRepr,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;
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
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        self.private_update_node_key(target_leaf, new_key, append_changes)
            .map(|(_, change, _)| change)
    }

    fn add_node(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
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
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let user_secret_key = self.private_art.get_leaf_secret_key()?;
        let user_public_key = self.private_art.get_leaf_public_key()?;

        let (_, change, artefacts) =
            self.private_art
                .private_update_node_key(target_leaf, new_key, append_changes)?;

        let proof = art_prove(
            self.proof_basis.clone(),
            ad,
            &artefacts.to_prover_branch(self.rng)?,
            vec![user_public_key],
            vec![user_secret_key],
        )?;

        Ok(VerifiableBranchChange {
            branch_change: change,
            proof,
        })
    }

    fn add_node(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let user_secret_key = self.private_art.get_leaf_secret_key()?;
        let user_public_key = self.private_art.get_leaf_public_key()?;

        let (_, change, artefacts) = self.private_art.private_add_node(new_key)?;

        let proof = art_prove(
            self.proof_basis.clone(),
            ad,
            &artefacts.to_prover_branch(self.rng)?,
            vec![user_public_key],
            vec![user_secret_key],
        )?;

        Ok({
            VerifiableBranchChange {
                branch_change: change,
                proof,
            }
        })
    }
}
