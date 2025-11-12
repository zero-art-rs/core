use crate::art::{PrivateZeroArt, PublicZeroArt};
use crate::changes::aggregations::AggregatedChange;
use crate::changes::branch_change::BranchChange;
use crate::errors::ArtError;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use zrt_zk::EligibilityRequirement;
use zrt_zk::aggregated_art::VerifierAggregationTree;
use zrt_zk::art::ArtProof;

/// Describes an ART change, which can be verified.
///
/// Verification requires the next input:
/// - `art` - the current of the ART
/// - `ad` - the associated auxiliary data used in proof
/// - `eligibility_requirement` - an eligibility requirement defining the update right of the proof creator
/// - `proof` - proof which will be verified
pub trait VerifiableChange<T> {
    /// Fail if proof is invalid. Else returns `Ok(())`.
    fn verify(
        &self,
        art: &T,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError>;
}

impl VerifiableChange<PublicZeroArt<CortadoAffine>> for BranchChange<CortadoAffine> {
    fn verify(
        &self,
        art: &PublicZeroArt<CortadoAffine>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let verification_branch = art
            .base_art
            .compute_artefacts_for_verification(self)?
            .to_verifier_branch()?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify(proof, &verification_branch)?;

        Ok(())
    }
}

impl<R> VerifiableChange<PrivateZeroArt<CortadoAffine, R>> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn verify(
        &self,
        art: &PrivateZeroArt<CortadoAffine, R>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let verification_branch = art
            .upstream_art
            .get_public_art()
            .compute_artefacts_for_verification(self)?
            .to_verifier_branch()?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify(proof, &verification_branch)?;

        Ok(())
    }
}

impl VerifiableChange<PublicZeroArt<CortadoAffine>> for AggregatedChange<CortadoAffine> {
    fn verify(
        &self,
        art: &PublicZeroArt<CortadoAffine>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let extracted_agg = self.add_co_path(&art.base_art)?;
        let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify_aggregated(&verifier_tree, proof)?;

        Ok(())
    }
}

impl<R> VerifiableChange<PrivateZeroArt<CortadoAffine, R>> for AggregatedChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn verify(
        &self,
        art: &PrivateZeroArt<CortadoAffine, R>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let extracted_agg = self.add_co_path(&art.base_art.public_art)?;
        let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify_aggregated(&verifier_tree, proof)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::art::PrivateArt;
    use crate::art::{AggregationContext, ArtAdvancedOps, PrivateZeroArt};
    use crate::art_node::TreeMethods;
    use crate::changes::aggregations::{
        AggregatedChange, AggregationData, AggregationTree, VerifierAggregationData,
    };
    use crate::changes::branch_change::BranchChange;
    use crate::changes::provable_change::ProvableChange;
    use crate::changes::{ApplicableChange, VerifiableChange};
    use crate::init_tracing;
    use crate::node_index::NodeIndex;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use ark_std::UniformRand;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use cortado::{CortadoAffine, Fr};
    use std::ops::Mul;
    use tracing::{debug, info, trace};
    use zrt_zk::EligibilityRequirement;
    use zrt_zk::art::ArtProof;

    const DEFAULT_TEST_GROUP_SIZE: i32 = 10;

    #[test]
    fn test_key_update_proof() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let mut main_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let mut art = PrivateZeroArt::new(private_art, main_rng).unwrap();

        let mut test_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let test_art =
            PrivateZeroArt::new(PrivateArt::new(public_art, secrets[1]).unwrap(), test_rng)
                .unwrap();

        let new_secret_key = Fr::rand(&mut rng);
        let associated_data = b"Some data for proof";

        let key_update_change_output = art.update_key(new_secret_key).unwrap();
        key_update_change_output.apply(&mut art).unwrap();
        art.commit().unwrap();

        let proof = key_update_change_output
            .prove(associated_data, None)
            .unwrap();
        let mut proof_bytes = Vec::new();
        proof.serialize_compressed(&mut proof_bytes).unwrap();
        let key_update_change = BranchChange::from(key_update_change_output);

        assert_eq!(
            art.get_base_art().get_root().get_public_key(),
            CortadoAffine::generator()
                .mul(art.get_base_art().get_root_secret_key())
                .into_affine()
        );

        let eligibility_requirement = EligibilityRequirement::Member(
            test_art
                .get_base_art()
                .get_node(&key_update_change.node_index)
                .unwrap()
                .get_public_key(),
        );
        let deserialized_proof = ArtProof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
        let verification_result = key_update_change.verify(
            &test_art,
            associated_data,
            eligibility_requirement,
            &deserialized_proof,
        );

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );
    }

    #[test]
    fn test_make_blank_proof() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let main_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let mut art = PrivateZeroArt::new(private_art, main_rng).unwrap();

        let test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            Box::new(StdRng::seed_from_u64(rand::random())),
        )
        .unwrap();

        let target_public_key = CortadoAffine::generator().mul(secrets[1]).into_affine();
        let target_node_path = art
            .get_base_art()
            .get_path_to_leaf_with(target_public_key)
            .unwrap();
        let target_node_index = NodeIndex::from(target_node_path);
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];

        let make_blank_change_output = art
            .remove_member(&target_node_index, new_secret_key)
            .unwrap();
        make_blank_change_output.apply(&mut art).unwrap();

        let proof = make_blank_change_output
            .prove(associated_data, None)
            .unwrap();
        let make_blank_change = BranchChange::from(make_blank_change_output);

        let tk = art.get_base_art().get_root_secret_key();

        let eligibility_requirement =
            EligibilityRequirement::Previleged((art.get_base_art().get_leaf_public_key(), vec![]));
        let verification_result =
            make_blank_change.verify(&test_art, associated_data, eligibility_requirement, &proof);

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );
    }

    #[test]
    fn test_append_node_proof() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let main_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let mut art = PrivateZeroArt::new(private_art, main_rng).unwrap();

        let test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            Box::new(StdRng::seed_from_u64(rand::random())),
        )
        .unwrap();

        let secret_key = art.get_base_art().get_leaf_secret_key();
        let public_key = art.get_base_art().get_leaf_public_key();
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];

        let append_node_changes_output = art.add_member(new_secret_key).unwrap();

        append_node_changes_output.apply(&mut art).unwrap();
        art.commit().unwrap();

        let proof = append_node_changes_output
            .prove(associated_data, None)
            .unwrap();

        let append_node_changes = BranchChange::from(append_node_changes_output);

        let eligibility_requirement = EligibilityRequirement::Previleged((public_key, vec![]));
        let verification_result =
            append_node_changes.verify(&test_art, associated_data, eligibility_requirement, &proof);

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );
    }

    #[test]
    fn test_append_node_after_make_blank_proof() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        // Use power of two, so all branches have equal weight. Then any blank node will be the
        // one to be replaced at node addition.
        let art_size = 2usize.pow(3);
        let secrets = (0..art_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let main_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let mut art = PrivateZeroArt::new(private_art, main_rng).unwrap();

        let test_rng = Box::new(StdRng::seed_from_u64(rand::random()));
        let mut test_art =
            PrivateZeroArt::new(PrivateArt::new(public_art, secrets[1]).unwrap(), test_rng)
                .unwrap();

        // let secret_key = art.get_base_art().get_leaf_secret_key();
        let public_key = art.get_base_art().get_leaf_public_key();
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data1 = b"asdlkfhalkehafksjdhkflasfsadfsdf";
        let associated_data2 = b"sdfksdhfjasdfaskhekjfaskldfsdfdf";

        // Make blank the node with index 1
        let target_public_key = CortadoAffine::generator().mul(secrets[4]).into_affine();
        let target_node_path = art
            .get_base_art()
            .get_path_to_leaf_with(target_public_key)
            .unwrap();
        let target_node_index = NodeIndex::from(target_node_path);

        let make_blank_changes_output = art
            .remove_member(&target_node_index, new_secret_key)
            .unwrap();
        make_blank_changes_output.apply(&mut art).unwrap();
        art.commit().unwrap();

        let proof1 = make_blank_changes_output
            .prove(associated_data1, None)
            .unwrap();
        let make_blank_changes = BranchChange::from(make_blank_changes_output);

        let eligibility_requirement =
            EligibilityRequirement::Previleged((art.get_base_art().get_leaf_public_key(), vec![]));
        let verification_result = make_blank_changes.verify(
            &test_art,
            associated_data1,
            eligibility_requirement,
            &proof1,
        );

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );

        make_blank_changes.apply(&mut test_art).unwrap();
        test_art.commit().unwrap();

        assert_eq!(
            public_key,
            CortadoAffine::generator()
                .mul(art.base_art.get_leaf_secret_key())
                .into_affine(),
        );
        assert_eq!(
            art.get_base_art()
                .get_node(art.get_node_index())
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(art.base_art.get_leaf_secret_key())
                .into_affine()
        );

        let append_node_changes_output = art.add_member(new_secret_key).unwrap();
        append_node_changes_output.apply(&mut art).unwrap();
        art.commit().unwrap();

        assert_eq!(
            public_key,
            art.get_base_art()
                .get_node(art.get_node_index())
                .unwrap()
                .get_public_key(),
        );
        assert_eq!(
            art.get_base_art()
                .get_node(art.get_node_index())
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(art.base_art.get_leaf_secret_key())
                .into_affine()
        );

        let proof2 = append_node_changes_output
            .prove(associated_data2, None)
            .unwrap();
        let append_node_changes = BranchChange::from(append_node_changes_output);

        let eligibility_requirement =
            EligibilityRequirement::Previleged((art.get_base_art().get_leaf_public_key(), vec![]));
        let verification_result = append_node_changes.verify(
            &test_art,
            associated_data2,
            eligibility_requirement,
            &proof2,
        );

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );
    }

    #[test]
    fn test_branch_aggregation_proof_verify() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = (0..group_length)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let mut user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(user0, user0_rng).unwrap();
        let mut user1 = PrivateArt::<CortadoAffine>::new(
            user0.get_base_art().get_public_art().clone(),
            secrets[1],
        )
        .unwrap();

        let target_3 = user0
            .get_base_art()
            .get_public_art()
            .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
            .unwrap();
        // Create aggregation
        let mut agg = AggregationContext::new(user0.get_base_art().clone(), Box::new(thread_rng()));

        for i in 0..4 {
            agg.add_member(Fr::rand(&mut rng)).unwrap();
        }

        let associated_data = b"data";

        let mut proof_bytes = Vec::new();
        agg.prove(associated_data, None)
            .unwrap()
            .serialize_compressed(&mut proof_bytes)
            .unwrap();

        let plain_agg = AggregatedChange::try_from(&agg).unwrap();

        let aux_pk = user0.get_base_art().get_leaf_public_key();
        let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
        let decoded_proof = ArtProof::deserialize_compressed(&*proof_bytes).unwrap();
        plain_agg
            .verify(
                &user0,
                associated_data,
                eligibility_requirement,
                &decoded_proof,
            )
            .unwrap();

        let plain_agg = AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let fromed_agg = AggregationTree::<VerifierAggregationData<CortadoAffine>>::try_from(
            &agg.prover_aggregation,
        )
        .unwrap();

        let extracted_agg = plain_agg
            .add_co_path(&agg.operation_tree.get_public_art())
            .unwrap();
        assert_eq!(
            fromed_agg, extracted_agg,
            "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
            fromed_agg, extracted_agg,
        );

        plain_agg.apply(&mut user1).unwrap();

        assert_eq!(agg.operation_tree, user1);
    }

    #[test]
    fn test_branch_aggregation_with_public_art() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = (0..group_length)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let mut user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(user0, user0_rng).unwrap();
        let mut user1 = PrivateArt::<CortadoAffine>::new(
            user0.get_base_art().get_public_art().clone(),
            secrets[1],
        )
            .unwrap();

        let target_3 = user0
            .get_base_art()
            .get_public_art()
            .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
            .unwrap();
        // Create aggregation
        let mut agg = AggregationContext::new(user0.get_base_art().clone(), Box::new(thread_rng()));

        for i in 0..4 {
            agg.add_member(Fr::rand(&mut rng)).unwrap();
        }

        let associated_data = b"data";

        let mut proof_bytes = Vec::new();
        agg.prove(associated_data, None)
            .unwrap()
            .serialize_compressed(&mut proof_bytes)
            .unwrap();

        let plain_agg = AggregatedChange::try_from(&agg).unwrap();

        let aux_pk = user0.get_base_art().get_leaf_public_key();
        let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
        let decoded_proof = ArtProof::deserialize_compressed(&*proof_bytes).unwrap();
        plain_agg
            .verify(
                &user0,
                associated_data,
                eligibility_requirement,
                &decoded_proof,
            )
            .unwrap();

        let plain_agg = AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let fromed_agg = AggregationTree::<VerifierAggregationData<CortadoAffine>>::try_from(
            &agg.prover_aggregation,
        )
            .unwrap();

        let extracted_agg = plain_agg
            .add_co_path(&agg.operation_tree.get_public_art())
            .unwrap();
        assert_eq!(
            fromed_agg, extracted_agg,
            "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
            fromed_agg, extracted_agg,
        );

        plain_agg.apply(&mut user1).unwrap();

        assert_eq!(agg.operation_tree, user1);
    }
}
