use crate::art::art_types::{PrivateZeroArt, PublicZeroArt};
use crate::changes::applicable_change::ApplicableChange;
use crate::changes::branch_change::BranchChange;
use crate::errors::ArtError;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use zrt_zk::EligibilityRequirement;
use zrt_zk::aggregated_art::{VerifierAggregationTree};
use zrt_zk::art::ArtProof;
use crate::changes::aggregations::PlainChangeAggregation;

pub trait VerifiableChange<T>: ApplicableChange<T> {
    fn verify(
        &self,
        art: &T,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError>;

    fn verify_then_update(
        &self,
        art: &mut T,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        self.verify(&*art, ad, eligibility_requirement, proof)?;
        self.update(art)?;

        Ok(())
    }
}

impl VerifiableChange<PublicZeroArt> for BranchChange<CortadoAffine> {
    fn verify(
        &self,
        art: &PublicZeroArt,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let verification_branch = art
            .get_public_art()
            .compute_artefacts_for_verification(self)?
            .to_verifier_branch()?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify(proof, &verification_branch)?;

        Ok(())
    }
}

impl<'a, R> VerifiableChange<PrivateZeroArt<'a, R>> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn verify(
        &self,
        art: &PrivateZeroArt<'a, R>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let verification_branch = art
            .get_public_art()
            .compute_artefacts_for_verification(self)?
            .to_verifier_branch()?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify(proof, &verification_branch)?;

        Ok(())
    }
}

impl VerifiableChange<PublicZeroArt> for PlainChangeAggregation<CortadoAffine> {
    fn verify(
        &self,
        art: &PublicZeroArt,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let extracted_agg = self.add_co_path(&art.public_art)?;
        let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify_aggregated(&verifier_tree, proof)?;

        Ok(())
    }
}

impl<'a, R> VerifiableChange<PrivateZeroArt<'a, R>>
    for PlainChangeAggregation<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn verify(
        &self,
        art: &PrivateZeroArt<'a, R>,
        ad: &[u8],
        eligibility_requirement: EligibilityRequirement,
        proof: &ArtProof,
    ) -> Result<(), ArtError> {
        let extracted_agg = self.add_co_path(&art.private_art.public_art)?;
        let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg)?;

        let verifier_context = art.verifier_engine.new_context(ad, eligibility_requirement);
        verifier_context.verify_aggregated(&verifier_tree, proof)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::TreeMethods;
    use crate::art::ArtAdvancedOps;
    use crate::art::art_types::{PrivateArt, PrivateZeroArt};
    use crate::changes::{ApplicableChange, VerifiableChange};
    use crate::init_tracing;
    use crate::node_index::NodeIndex;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use std::ops::Mul;
    use zrt_zk::EligibilityRequirement;
    use crate::changes::branch_change::{BranchChange};
    use crate::changes::provable_change::ProvableChange;

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

        let mut main_rng = StdRng::seed_from_u64(rand::random());
        let mut art = PrivateZeroArt::new(private_art.clone(), &mut main_rng);

        let mut test_rng = StdRng::seed_from_u64(rand::random());
        let test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            &mut test_rng,
        );

        let new_secret_key = Fr::rand(&mut rng);
        let associated_data = b"Some data for proof";

        let key_update_change_output = art
            .update_key(new_secret_key)
            .unwrap();
        
        let proof = key_update_change_output.prove(&mut art, associated_data, None).unwrap();
        let key_update_change = BranchChange::from(key_update_change_output);

        assert_eq!(
            art.get_root().get_public_key(),
            CortadoAffine::generator()
                .mul(art.get_root_secret_key().unwrap())
                .into_affine()
        );

        let eligibility_requirement = EligibilityRequirement::Member(
            test_art
                .get_node(&key_update_change.node_index)
                .unwrap()
                .get_public_key(),
        );
        let verification_result =
            key_update_change.verify(&test_art, associated_data, eligibility_requirement, &proof);

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

        let mut private_art = PrivateArt::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let mut main_rng = StdRng::seed_from_u64(rand::random());
        let mut art = PrivateZeroArt::new(private_art.clone(), &mut main_rng);

        let mut test_rng = StdRng::seed_from_u64(rand::random());
        let test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            &mut test_rng,
        );

        let secret_key = art.get_leaf_secret_key().unwrap();
        let secret_key = art.get_leaf_public_key().unwrap();

        let target_public_key = CortadoAffine::generator().mul(secrets[1]).into_affine();
        let target_node_path = art.get_path_to_leaf_with(target_public_key).unwrap();
        let target_node_index = NodeIndex::from(target_node_path);
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];

        let make_blank_change_output = art
            .remove_member(&target_node_index, new_secret_key)
            .unwrap();

        let proof = make_blank_change_output.prove(&mut art, associated_data, None).unwrap();
        let make_blank_change = BranchChange::from(make_blank_change_output);
        
        let tk = art.get_root_secret_key().unwrap();

        let eligibility_requirement =
            EligibilityRequirement::Member(art.get_leaf_public_key().unwrap());
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

        let mut main_rng = StdRng::seed_from_u64(rand::random());
        let mut art = PrivateZeroArt::new(private_art.clone(), &mut main_rng);

        let mut test_rng = StdRng::seed_from_u64(rand::random());
        let test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            &mut test_rng,
        );

        let secret_key = art.get_leaf_secret_key().unwrap();
        let public_key = art.get_leaf_public_key().unwrap();
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];

        let append_node_changes_output = art
            .add_member(new_secret_key)
            .unwrap();
        let proof = append_node_changes_output.prove(&mut art, associated_data, None).unwrap();
        let append_node_changes = BranchChange::from(append_node_changes_output);

        let eligibility_requirement =
            EligibilityRequirement::Member(art.get_leaf_public_key().unwrap());
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
        let mut rng = StdRng::seed_from_u64(rand::random());
        // Use power of two, so all branches have equal weight. Then any blank node will be the
        // one to be replaced at node addition.
        let art_size = 2usize.pow(7);
        let secrets = (0..art_size)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.get_public_art().clone();

        let mut main_rng = StdRng::seed_from_u64(rand::random());
        let mut art = PrivateZeroArt::new(private_art.clone(), &mut main_rng);

        let mut test_rng = StdRng::seed_from_u64(rand::random());
        let mut test_art = PrivateZeroArt::new(
            PrivateArt::new(public_art, secrets[1]).unwrap(),
            &mut test_rng,
        );

        let secret_key = art.get_leaf_secret_key().unwrap();
        let public_key = art.get_leaf_public_key().unwrap();
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data1 = b"asdlkfhalkehafksjdhkflasfsadfsdf";
        let associated_data2 = b"sdfksdhfjasdfaskhekjfaskldfsdfdf";

        // Make blank the node with index 1
        let target_public_key = CortadoAffine::generator().mul(secrets[4]).into_affine();
        let target_node_path = art.get_path_to_leaf_with(target_public_key).unwrap();
        let target_node_index = NodeIndex::from(target_node_path);
        let make_blank_changes_output = art
            .remove_member(&target_node_index, new_secret_key)
            .unwrap();
        let proof1 = make_blank_changes_output.prove(&mut art, associated_data1, None).unwrap();
        let make_blank_changes = BranchChange::from(make_blank_changes_output);

        let eligibility_requirement =
            EligibilityRequirement::Member(art.get_leaf_public_key().unwrap());
        let verification_result =
            make_blank_changes.verify(&test_art, associated_data1, eligibility_requirement, &proof1);

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );

        make_blank_changes.update(&mut test_art).unwrap();

        let append_node_changes_output = art
            .add_member(new_secret_key)
            .unwrap();
        let proof2 = append_node_changes_output.prove(&mut art, associated_data2, None).unwrap();
        let append_node_changes = BranchChange::from(append_node_changes_output);

        let eligibility_requirement =
            EligibilityRequirement::Member(art.get_leaf_public_key().unwrap());
        let verification_result =
            append_node_changes.verify(&test_art, associated_data2, eligibility_requirement, &proof2);

        assert!(
            matches!(verification_result, Ok(())),
            "Must successfully verify, while get {:?} result",
            verification_result
        );
    }
}
