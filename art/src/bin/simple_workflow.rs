use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use cortado::{CortadoAffine, Fr};
use postcard::{from_bytes, to_allocvec};
use std::ops::Mul;
use zrt_art::TreeMethods;
use zrt_art::art::{AggregationContext, ArtAdvancedOps, PrivateZeroArt};
use zrt_art::art::art_types::{PrivateArt, PublicArt};
use zrt_art::changes::aggregations::{AggregatedChange};
use zrt_art::changes::branch_change::{BranchChange};
use zrt_art::changes::{ApplicableChange, ProvableChange, VerifiableChange};
use zrt_art::node_index::NodeIndex;
use zrt_zk::EligibilityRequirement;

/// PrivateArt usage example. PrivateArt contain handle key management, while ART isn't.
fn general_example() {
    let number_of_users = 8;
    let generator = CortadoAffine::generator();
    let mut rng = StdRng::seed_from_u64(rand::random());

    // To create a new tree, the creator of a group will create a set of invitations.
    // Those invitations contain leaf secret keys, which are elements of curve scalar field.
    // Note, that the first secret in a set, must be a creators secret key, because the
    // owner of group is defined as a left most node in a tree.
    let secrets: Vec<Fr> = (0..number_of_users)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    // For new art, creator provides the next method with set of secrets and some generator.
    let art = PrivateArt::setup(&secrets).unwrap();
    let mut zero_art_rng = Box::new(thread_rng());
    let zero_art = PrivateZeroArt::new(art.clone(), zero_art_rng).unwrap();

    // PublicArt implements Derive for serialization.
    let encoded_representation = to_allocvec(art.get_public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&encoded_representation).unwrap();

    // When rhe user receives his art, he can derive a new PrivateArt with his leaf secret key.
    let recovered_private_art = PrivateArt::new(public_art.clone(), secrets[0]).unwrap();
    let mut recovered_art_rng = Box::new(thread_rng());
    let recovered_art = PrivateZeroArt::new(recovered_private_art, recovered_art_rng).unwrap();

    assert_eq!(recovered_art, zero_art);

    // Assume art_i is i-th user art, which also knows i-th secret key.
    let mut art_0_rng = Box::new(thread_rng());
    let mut art_0 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[0]).unwrap(),
        art_0_rng,
    ).unwrap();
    let mut art_1_rng = Box::new(thread_rng());
    let mut art_1 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[1]).unwrap(),
        art_1_rng,
    ).unwrap();
    let new_secret_key_1 = Fr::rand(&mut rng);

    // Any user can update his public art with the next method.
    let output_1 = art_1.update_key(new_secret_key_1).unwrap();
    // Apply ephemeral operation to the ART tree with private branch change.
    output_1.apply(&mut art_1).unwrap();
    art_1.commit();

    // Retrieve change from the private branch change
    let change_1 = BranchChange::from(output_1);


    // Root key tk is a new common secret. To get common secret, user should use the next method.
    let _retrieved_tk_1 = art_0.get_base_art().get_root_secret_key();

    // Other users can use returned change to update local tree. Fot example, this can be done as next:
    change_1.apply(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // Other art modifications include addition and blanking.
    // Addition of a new node can be done as next:
    let new_node1_secret_key = Fr::rand(&mut rng);
    let output_2 = art_1.add_member(new_node1_secret_key).unwrap();
    let changes_2 = BranchChange::from(output_2);

    changes_2.apply(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // Remove member from the tree, by making his node temporary.
    let new_node1_public_key = generator.mul(new_node1_secret_key).into_affine();
    let some_secret_key1 = Fr::rand(&mut rng);
    let target_node_path = art_1
        .get_base_art()
        .get_public_art()
        .get_path_to_leaf_with(new_node1_public_key)
        .unwrap();
    let target_node_index = NodeIndex::from(target_node_path);
    let output_3 = art_1
        .remove_member(&target_node_index, some_secret_key1)
        .unwrap();
    let changes_3 = BranchChange::from(output_3);
    changes_3.apply(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // For proof generation, use pass required data for proof creation, to change creation method.
    // Here is an example for key update:
    let associated_data = b"associated data";
    let some_secret_key4 = Fr::rand(&mut rng);
    let output_4 = art_1.update_key(some_secret_key4).unwrap();
    let proof = output_4.prove(associated_data, None).unwrap();
    let changes_4 = BranchChange::from(output_4);

    // To verify the change, one pass eligibility_requirement with proof to verify method.
    let eligibility_requirement = EligibilityRequirement::Member(
        art_0
            .get_base_art()
            .get_node(&changes_4.node_index)
            .unwrap()
            .get_public_key(),
    );
    let verification_result =
        changes_4.verify(&art_0, associated_data, eligibility_requirement, &proof);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );

    assert!(verification_result.is_ok());
}

// fn merge_conflict_changes() {
//     let mut rng = &mut StdRng::seed_from_u64(0);
//     let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
//
//     let art0 = PrivateArt::setup(&secrets).unwrap();
//     let public_art = art0.get_public_art().clone();
//
//     // Store the basic art1.
//     let art1: PrivateArt<CortadoAffine> = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();
//
//     // Create new users arts
//     let mut user0 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[0]).unwrap();
//     let mut user2 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[2]).unwrap();
//     let mut user3 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[8]).unwrap();
//
//     let sk0 = Fr::rand(&mut rng);
//     let change0 = user0.update_key(sk0).unwrap();
//
//     let sk2 = Fr::rand(&mut rng);
//     let change2 = user2.update_key(sk2).unwrap();
//
//     let sk3 = Fr::rand(&mut rng);
//     let change3 = user3.update_key(sk3).unwrap();
//
//     let applied_change = change0.clone();
//     let all_but_0_changes = vec![change2.clone(), change3.clone()];
//     let all_changes = vec![change0, change2, change3];
//
//     // Merge for users which participated in the merge
//     let mut participant = user0.clone();
//     let participant_merge_change = MergeBranchChange::new_for_participant(
//         art0.clone(),
//         applied_change.clone(),
//         all_but_0_changes.clone(),
//     );
//     participant_merge_change.apply(&mut participant).unwrap();
//
//     // Merge for users which only observed the merge conflict
//     let mut observer = art1.clone();
//     let observer_merge_change = MergeBranchChange::new_for_observer(all_changes);
//     observer_merge_change.apply(&mut observer).unwrap();
//
//     assert_eq!(
//         participant, observer,
//         "Observer and participant have the same view on the state of the art."
//     );
// }

fn branch_aggregation_proof_verify() {
    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let art0 = PrivateArt::setup(&secrets).unwrap();

    // Create a different user.
    let mut art1 =
        PrivateArt::<CortadoAffine>::new(art0.get_public_art().clone(), secrets[1]).unwrap();

    // Define some target user, to be removed.
    let target_3 = art0
        .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    let target_3_index = NodeIndex::from(target_3);

    // Create zero_art to create proofs.
    let mut zero_art0 = PrivateZeroArt::new(
        art0,
        Box::new(thread_rng())
    ).unwrap();

    // Create default aggregation
    let mut agg = AggregationContext::from_private_zero_art(
        &zero_art0,
        Box::new(thread_rng())
    );

    // Perform some changes
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.remove_member(&target_3_index, Fr::rand(&mut rng))
        .unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.leave_group(Fr::rand(&mut rng)).unwrap();

    // Gather associated data
    let associated_data = b"associated data";

    // Create verifiable aggregation.
    let proof = agg.prove(associated_data, None).unwrap();
    let plain_agg = AggregatedChange::try_from(&agg).unwrap();

    // Aggregation verification is similar to usual change aggregation.
    let aux_pk = zero_art0.get_base_art().get_leaf_public_key();
    let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
    plain_agg
        .verify(&zero_art0, associated_data, eligibility_requirement, &proof)
        .unwrap();

    // Finally update private art with the `extracted_agg` aggregation.
    plain_agg.apply(&mut art1).unwrap();

    assert_eq!(zero_art0.get_upstream_art().get_public_art(), art1.get_public_art());
    assert_eq!(zero_art0.get_upstream_art().get_root_secret_key(), art1.get_root_secret_key());
}

fn branch_aggregation() {
    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let mut art0 = PrivateArt::setup(&secrets).unwrap();

    let mut art1 =
        PrivateArt::<CortadoAffine>::new(art0.get_public_art().clone(), secrets[1]).unwrap();

    let target_3 = art0
        .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();

    // Create default aggregation
    let mut agg = AggregatedChange::default();

    // Perform some changes
    agg.add_member(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.remove_member(&target_3, Fr::rand(&mut rng), &mut art0)
        .unwrap();
    agg.update_key(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.add_member(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.leave(Fr::rand(&mut rng), &mut art0).unwrap();

    // Finally update private art with the `agg` plain aggregation.
    agg.apply(&mut art1).unwrap();

    assert_eq!(art0.get_public_art(), art1.get_public_art());
    assert_eq!(art0.get_root_secret_key(), art1.get_root_secret_key());
}

fn main() {
    general_example();
    // merge_conflict_changes();
    branch_aggregation_proof_verify();
    branch_aggregation();
}
