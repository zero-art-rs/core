use crate::TreeMethods;
use crate::art::art_node::LeafStatus;
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::changes::aggregations::{AggregatedChange};
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine};

/// A trait for ART change that can be applied to the ART.
///
/// This trait represents an ability of change to update some instance of ART of type `T`.
///
/// # Type Parameters
/// * `T` – The type of the ART tree type being updated.
pub trait ApplicableChange<T, G>
where
    G: AffineRepr,
{
    /// Apply a change to the provided art.
    fn apply(&self, art: &mut T) -> Result<(), ArtError>;
}

impl<G> ApplicableChange<PublicArt<G>, G> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && let Some(LeafStatus::Blank) = art.get_node(&self.node_index)?.get_status()
        {
            art.update_with_options(self, true, false)
        } else {
            art.update_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && matches!(
                art.public_art.get_node(&self.node_index)?.get_status(),
                Some(LeafStatus::Blank)
            )
        {
            art.update_private_art_with_options(self, true, false)
        } else {
            art.update_private_art_with_options(self, false, true)
        }
    }
}

impl ApplicableChange<PublicZeroArt, CortadoAffine> for BranchChange<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.apply(&mut art.public_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>, CortadoAffine> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        self.apply(&mut art.private_art)
    }
}

impl<G> ApplicableChange<PublicArt<G>, G> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        self.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        self.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt, CortadoAffine> for AggregatedChange<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.update_public_art(&mut art.public_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>, CortadoAffine> for AggregatedChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        self.update_private_art(&mut art.private_art)
    }
}
