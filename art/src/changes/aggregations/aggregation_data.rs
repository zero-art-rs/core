use crate::changes::branch_change::{BranchChangeType, BranchChangeTypeHint};
use crate::helper_tools::prepare_short_marker_for_option;
use crate::helper_tools::{ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use zrt_zk::art::{ProverNodeData, VerifierNodeData};

/// Helper structure. Can be stored in aggregation tree. Contains all the public keys, required
/// to update art and create proofs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct ProverAggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: G,

    /// Public key of the neighbour of the node for every `public_key` except root. For root, if
    /// it is empty.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_public_key: Option<G>,

    /// Secret key of corresponding `public_key`
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub secret_key: G::ScalarField,

    /// Change type marker
    pub change_type: Vec<BranchChangeTypeHint<G>>,
}

impl<G> ProverAggregationData<G>
where
    G: AffineRepr,
{
    pub(crate) fn aggregate(
        &mut self,
        public_key: G,
        co_public_key: Option<G>,
        secret_key: G::ScalarField,
        change_type: Option<BranchChangeTypeHint<G>>,
    ) {
        self.public_key = public_key;
        self.secret_key = secret_key;
        self.co_public_key = co_public_key;

        if let Some(change_type) = change_type {
            self.change_type.push(change_type);
        }
    }

    pub(crate) fn aggregate_with(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.secret_key = other.secret_key;
        self.co_public_key = other.co_public_key;
        self.change_type.extend(other.change_type);
    }

    pub(crate) fn update_change_type(&mut self, change_type: BranchChangeTypeHint<G>) {
        self.change_type.push(change_type);
    }
}

/// Helper structure. Stores all the updated public keys by the user.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct AggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: G,

    /// Change type marker
    pub change_type: Vec<BranchChangeTypeHint<G>>,
}

impl<G> AggregationData<G>
where
    G: AffineRepr,
{
    pub(crate) fn aggregate(&mut self, other: Self) {
        self.public_key = other.public_key;
        self.change_type.extend(other.change_type);
    }
}

/// Helper structure. Similar to `AggregationData`, but with additional co-path values for
/// proof verification.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct VerifierAggregationData<G>
where
    G: AffineRepr,
{
    /// Public keys of the node from all the changes.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub public_key: G,

    // Public key of the neighbour of the node for every `public_key` except root. For root, if is empty.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub co_public_key: Option<G>,

    /// Change type marker
    pub change_type: Vec<BranchChangeTypeHint<G>>,
}

impl<G> Display for ProverAggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = prepare_short_marker_for_option(&self.public_key.x());

        let co_pk_marker =
            prepare_short_marker_for_option(&self.co_public_key.and_then(|co_pk| co_pk.x()));

        let sk_marker = prepare_short_marker_for_option(&Some(self.secret_key));

        write!(
            f,
            "pk: {}, co_pk: {}, sk: {}, type: {:?}",
            pk_marker,
            co_pk_marker,
            sk_marker,
            self.change_type
                .iter()
                .map(BranchChangeType::from)
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> Display for VerifierAggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = prepare_short_marker_for_option(&self.public_key.x());

        let co_pk_marker =
            prepare_short_marker_for_option(&self.co_public_key.and_then(|co_pk| co_pk.x()));

        write!(
            f,
            "pk: {}, co_pk: {}, type: {:?}",
            pk_marker,
            co_pk_marker,
            self.change_type
                .iter()
                .map(BranchChangeType::from)
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> Display for AggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = prepare_short_marker_for_option(&self.public_key.x());

        write!(
            f,
            "pk: {}, type: {:?}",
            pk_marker,
            self.change_type
                .iter()
                .map(BranchChangeType::from)
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> From<&ProverAggregationData<G>> for ProverNodeData<G>
where
    G: AffineRepr,
{
    fn from(value: &ProverAggregationData<G>) -> Self {
        Self {
            public_key: value.public_key,
            co_public_key: value.co_public_key,
            secret_key: value.secret_key,
        }
    }
}

impl<G> From<&VerifierAggregationData<G>> for VerifierNodeData<G>
where
    G: AffineRepr,
{
    fn from(value: &VerifierAggregationData<G>) -> Self {
        Self {
            public_key: value.public_key,
            co_public_key: value.co_public_key,
        }
    }
}

impl<G> From<ProverAggregationData<G>> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn from(prover_data: ProverAggregationData<G>) -> Self {
        Self {
            public_key: prover_data.public_key,
            co_public_key: prover_data.co_public_key,
            change_type: prover_data.change_type,
        }
    }
}

impl<G> From<ProverAggregationData<G>> for AggregationData<G>
where
    G: AffineRepr,
{
    fn from(prover_data: ProverAggregationData<G>) -> Self {
        Self {
            public_key: prover_data.public_key,
            change_type: prover_data.change_type,
        }
    }
}

impl<G> From<VerifierAggregationData<G>> for AggregationData<G>
where
    G: AffineRepr,
{
    fn from(verifier_data: VerifierAggregationData<G>) -> Self {
        Self {
            public_key: verifier_data.public_key,
            change_type: verifier_data.change_type,
        }
    }
}

impl<G> From<AggregationData<G>> for VerifierAggregationData<G>
where
    G: AffineRepr,
{
    fn from(aggregation_data: AggregationData<G>) -> Self {
        Self {
            public_key: aggregation_data.public_key,
            co_public_key: None,
            change_type: aggregation_data.change_type,
        }
    }
}
