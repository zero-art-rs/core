use crate::errors::ARTError;
use crate::zrt_art::art_node::LeafStatus;
use crate::zrt_art::art_types::{PrivateArt, PublicArt};
use crate::zrt_art::branch_change::{BranchChanges, BranchChangesType};
use crate::zrt_art::tree_node::TreeMethods;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

pub trait ApplicableChange<T> {
    fn update(&self, art: &mut T) -> Result<(), ARTError>;
}

impl<G> ApplicableChange<PublicArt<G>> for BranchChanges<G>
where
    G: AffineRepr,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = self.change_type
            && let Some(LeafStatus::Blank) = art.get_node(&self.node_index)?.get_status()
        {
            art.update_with_options(self, true, false)
        } else {
            art.update_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for BranchChanges<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = self.change_type
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
