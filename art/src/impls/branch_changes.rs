use crate::types::BranchChangesTypeHint;
use crate::{
    errors::ARTError,
    types::{BranchChanges, BranchChangesType},
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};

impl<G> BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(self).map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, ARTError> {
        from_bytes(bytes).map_err(ARTError::Postcard)
    }
}

impl Default for BranchChangesType {
    fn default() -> Self {
        Self::UpdateKey
    }
}

impl<G> TryFrom<BranchChangesTypeHint<G>> for BranchChangesType
where
    G: AffineRepr,
{
    type Error = ARTError;

    fn try_from(value: BranchChangesTypeHint<G>) -> Result<Self, Self::Error> {
        match value {
            BranchChangesTypeHint::MakeBlank { .. } => Ok(BranchChangesType::MakeBlank),
            BranchChangesTypeHint::AppendNode { .. } => Ok(BranchChangesType::AppendNode),
            BranchChangesTypeHint::UpdateKey { .. } => Ok(BranchChangesType::UpdateKey),
            _ => Err(ARTError::InvalidInput),
        }
    }
}
