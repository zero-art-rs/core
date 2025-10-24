use crate::errors::ARTError;
use crate::zrt_art::art_node::LeafStatus;
use crate::zrt_art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::zrt_art::branch_change::{BranchChange, BranchChangeType, VerifiableBranchChange};
use crate::zrt_art::tree_methods::TreeMethods;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::CortadoAffine;

pub trait ApplicableChange<T> {
    fn update(&self, art: &mut T) -> Result<(), ARTError>;
}

impl<G> ApplicableChange<PublicArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ARTError> {
        if let BranchChangeType::MakeBlank = self.change_type
            && let Some(LeafStatus::Blank) = art.get_node(&self.node_index)?.get_status()
        {
            art.update_with_options(self, true, false)
        } else {
            art.update_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ARTError> {
        if let BranchChangeType::MakeBlank = self.change_type
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

impl ApplicableChange<PublicZeroArt> for BranchChange<CortadoAffine> {
    fn update(&self, art: &mut PublicZeroArt) -> Result<(), ARTError> {
        self.update(&mut art.public_art)
    }
}

impl ApplicableChange<PublicZeroArt> for VerifiableBranchChange {
    fn update(&self, art: &mut PublicZeroArt) -> Result<(), ARTError> {
        self.branch_change.update(&mut art.public_art)
    }
}

impl<'a, R> ApplicableChange<PrivateZeroArt<'a, R>> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn update(&self, art: &mut PrivateZeroArt<'a, R>) -> Result<(), ARTError> {
        self.update(&mut art.private_art)
    }
}

impl<'a, R> ApplicableChange<PrivateZeroArt<'a, R>> for VerifiableBranchChange
where
    R: Rng + ?Sized,
{
    fn update(&self, art: &mut PrivateZeroArt<'a, R>) -> Result<(), ARTError> {
        self.branch_change.update(&mut art.private_art)
    }
}
