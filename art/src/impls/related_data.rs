use crate::traits::RelatedData;
use crate::types::{ProverAggregationData, VerifierAggregationData};
use ark_ec::AffineRepr;

impl<G> RelatedData for ProverAggregationData<G> where G: AffineRepr {}

impl<G> RelatedData for VerifierAggregationData<G> where G: AffineRepr {}
