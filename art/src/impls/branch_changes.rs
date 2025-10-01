use crate::{
    errors::ARTError,
    types::{AggregationChangeType, BranchChanges, BranchChangesType, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};

impl<G> BranchChanges<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub fn serialze(&self) -> Result<Vec<u8>, ARTError> {
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

impl From<AggregationChangeType> for BranchChangesType {
    fn from(change_type: AggregationChangeType) -> Self {
        match change_type {
            AggregationChangeType::UpdateKey => BranchChangesType::UpdateKey,
            AggregationChangeType::MakeBlank => BranchChangesType::MakeBlank,
            AggregationChangeType::MakeBlankThenAppendMember => BranchChangesType::AppendNode,
            AggregationChangeType::AppendNode => BranchChangesType::AppendNode,
            AggregationChangeType::AppendMemberThenUpdateKey => BranchChangesType::UpdateKey,
            AggregationChangeType::UpdateKeyThenAppendMember => BranchChangesType::AppendNode,
        }
    }
}
