use crate::art::art_types::{PrivateArt, PrivateZeroArt};
use crate::changes::branch_change::{ArtOperationOutput, BranchChange};
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
    ) -> Result<R, ArtError>;

    fn add_node(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;
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
    ) -> Result<BranchChange<G>, ArtError> {
        self.private_update_node_key(target_leaf, new_key, append_changes)
            .map(|(_, change, _)| change)
    }

    fn add_node(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        self.private_add_node(new_key).map(|(_, change, _)| change)
    }
}

impl<R> ArtBasicOps<CortadoAffine, ArtOperationOutput<CortadoAffine>> for PrivateZeroArt<R>
where
    R: ?Sized + Rng,
{
    fn update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        append_changes: bool,
    ) -> Result<ArtOperationOutput<CortadoAffine>, ArtError> {
        let eligibility =
            EligibilityArtefact::Member((self.get_leaf_secret_key(), self.get_leaf_public_key()));

        let (_, change, artefacts) =
            self.private_art
                .private_update_node_key(target_leaf, new_key, append_changes)?;

        Ok(ArtOperationOutput {
            branch_change: change,
            artefacts,
            eligibility,
        })
    }

    fn add_node(&mut self, new_key: Fr) -> Result<ArtOperationOutput<CortadoAffine>, ArtError> {
        let eligibility =
            EligibilityArtefact::Owner((self.get_leaf_secret_key(), self.get_leaf_public_key()));

        let (_, change, artefacts) = self.private_art.private_add_node(new_key)?;

        Ok(ArtOperationOutput {
            branch_change: change,
            artefacts,
            eligibility,
        })
    }
}
