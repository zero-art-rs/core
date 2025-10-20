use crate::types::{
    AggregationData, BranchChangesType, EmptyData, ProverAggregationData, VerifierAggregationData,
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::fmt::{Display, Formatter};
use zrt_zk::aggregated_art::{ProverAggregatedNodeData, VerifierAggregatedNodeData};

impl<G> Display for ProverAggregationData<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        let sk_marker = self
            .secret_key
            .to_string()
            .chars()
            .take(8)
            .collect::<String>()
            + "...";

        write!(
            f,
            "pk: {}, co_pk: {}, sk: {}, type: {:?}",
            pk_marker,
            co_pk_marker,
            sk_marker,
            self.change_type
                .iter()
                .map(|change_type| BranchChangesType::from(change_type))
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
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        let co_pk_marker = match self.co_public_key {
            Some(co_pk) => match co_pk.x() {
                Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
                None => "None".to_string(),
            },
            None => "None".to_string(),
        };

        write!(
            f,
            "pk: {}, co_pk: {}, type: {:?}",
            pk_marker,
            co_pk_marker,
            self.change_type
                .iter()
                .map(|change_type| BranchChangesType::from(change_type))
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
        let pk_marker = match self.public_key.x() {
            Some(x) => x.to_string().chars().take(8).collect::<String>() + "...",
            None => "None".to_string(),
        };

        write!(
            f,
            "pk: {}, type: {:?}",
            pk_marker,
            self.change_type
                .iter()
                .map(|change_type| BranchChangesType::from(change_type))
                .collect::<Vec<_>>(),
        )
    }
}

impl<G> From<&ProverAggregationData<G>> for ProverAggregatedNodeData<G>
where
    G: AffineRepr,
{
    fn from(value: &ProverAggregationData<G>) -> Self {
        Self {
            public_key: value.public_key,
            co_public_key: value.co_public_key,
            secret_key: value.secret_key,
            blinding_factor: value.blinding_factor,
            marker: false,
        }
    }
}

impl<G> From<&VerifierAggregationData<G>> for VerifierAggregatedNodeData<G>
where
    G: AffineRepr,
{
    fn from(value: &VerifierAggregationData<G>) -> Self {
        Self {
            public_key: value.public_key,
            co_public_key: value.co_public_key,
            marker: false,
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

impl<G> From<ProverAggregationData<G>> for EmptyData
where
    G: AffineRepr,
{
    fn from(_: ProverAggregationData<G>) -> Self {
        Self {}
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
