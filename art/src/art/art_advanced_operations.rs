use crate::errors::ArtError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;

/// Advanced ART operations like remove member, leave group, update key, etc.
pub trait ArtAdvancedOps<G, R>
where
    G: AffineRepr,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<R, ArtError>;

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;
}
