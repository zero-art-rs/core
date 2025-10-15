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

impl<G> From<&BranchChangesTypeHint<G>> for BranchChangesType
where
    G: AffineRepr,
{
    fn from(value: &BranchChangesTypeHint<G>) -> Self {
        match value {
            BranchChangesTypeHint::MakeBlank { .. } => BranchChangesType::MakeBlank,
            BranchChangesTypeHint::AppendNode { .. } => BranchChangesType::AppendNode,
            BranchChangesTypeHint::UpdateKey { .. } => BranchChangesType::UpdateKey,
        }
    }
}
