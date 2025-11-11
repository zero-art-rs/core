use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use cortado::{CortadoAffine, Fr};
use postcard::{from_bytes, to_allocvec};
use std::ops::Mul;
use zrt_art::art::{AggregationContext, ArtAdvancedOps, PrivateArt, PrivateZeroArt, PublicArt};
use zrt_art::art_node::TreeMethods;
use zrt_art::changes::aggregations::AggregatedChange;
use zrt_art::changes::branch_change::BranchChange;
use zrt_art::changes::{ApplicableChange, ProvableChange, VerifiableChange};
use zrt_art::node_index::NodeIndex;
use zrt_zk::EligibilityRequirement;

/// PrivateArt usage example. PrivateArt contain handle key management, while ART isn't.
fn example_of_simple_flow() {
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
    let zero_art_rng = Box::new(thread_rng());
    let zero_art = PrivateZeroArt::new(art.clone(), zero_art_rng).unwrap();

    // PublicArt implements Derive for serialization. For example one can serialize public art as next:
    let encoded_representation = to_allocvec(art.get_public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&encoded_representation).unwrap();

    // When rhe user receives his art, he can derive a new PrivateArt with his leaf secret key.
    let recovered_private_art = PrivateArt::new(public_art.clone(), secrets[0]).unwrap();
    let recovered_art_rng = Box::new(thread_rng());
    let recovered_art = PrivateZeroArt::new(recovered_private_art, recovered_art_rng).unwrap();

    assert_eq!(recovered_art, zero_art);

    // For example, assume art_i is i-th user art, which also knows i-th secret key.
    let mut art_0 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[0]).unwrap(),
        Box::new(thread_rng()),
    )
    .unwrap();

    let mut art_1 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[1]).unwrap(),
        Box::new(thread_rng()),
    )
    .unwrap();

    let new_secret_key_1 = Fr::rand(&mut rng);

    // Any user can update his public art with the next method.
    let output_1 = art_1.update_key(new_secret_key_1).unwrap();
    // Apply ephemeral operation to the ART tree with private branch change.
    output_1.apply(&mut art_1).unwrap();
    art_1.commit().unwrap();

    // Retrieve change from the private branch change
    let change_1 = BranchChange::from(output_1);

    // Root key tk is a new common secret. To get common secret, user should use the next method.
    let _retrieved_tk_1 = art_0.get_base_art().get_root_secret_key();

    // Other users can use returned change to update local tree. Fot example, this can be done as next:
    change_1.apply(&mut art_0).unwrap();
    art_0.commit().unwrap();
    assert_eq!(art_0, art_1);

    // Other art modifications include addition and blanking.
    // Addition of a new node can be done as next:
    let new_node1_secret_key = Fr::rand(&mut rng);
    let output_2 = art_1.add_member(new_node1_secret_key).unwrap();
    let change_2 = BranchChange::from(output_2);

    change_2.apply(&mut art_0).unwrap();
    art_0.commit().unwrap();
    change_2.apply(&mut art_1).unwrap();
    art_1.commit().unwrap();
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
    let change_3 = BranchChange::from(output_3);
    change_3.apply(&mut art_0).unwrap();
    art_0.commit().unwrap();
    change_3.apply(&mut art_1).unwrap();
    art_1.commit().unwrap();
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

fn example_of_merging_concurrent_changes() {
    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let creator_art = PrivateArt::setup(&secrets).unwrap();
    let public_art = creator_art.get_public_art().clone();

    // Create new users arts
    let mut user0 = PrivateZeroArt::new(creator_art, Box::new(thread_rng())).unwrap();

    let mut user1 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[1]).unwrap(),
        Box::new(thread_rng()),
    )
    .unwrap();

    let mut user2 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[2]).unwrap(),
        Box::new(thread_rng()),
    )
    .unwrap();

    let mut user3 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[8]).unwrap(),
        Box::new(thread_rng()),
    )
    .unwrap();

    // Create some concurrent changes
    let sk0 = Fr::rand(&mut rng);
    let private_change0 = user0.update_key(sk0).unwrap();
    let change0 = private_change0.get_branch_change().clone();

    let sk2 = Fr::rand(&mut rng);
    let private_change2 = user2.update_key(sk2).unwrap();
    let change2 = private_change2.get_branch_change().clone();

    let sk3 = Fr::rand(&mut rng);
    let private_change3 = user3.update_key(sk3).unwrap();
    let change3 = private_change3.get_branch_change().clone();

    let new_root = *change0.public_keys.first().unwrap()
        + *change2.public_keys.first().unwrap()
        + *change3.public_keys.first().unwrap();
    let new_root = new_root.into_affine();

    // Apply changes to ART trees. Use private_change to apply change of the user own key.
    private_change0.apply(&mut user0).unwrap();
    change2.apply(&mut user0).unwrap();
    change3.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    change0.apply(&mut user1).unwrap();
    change2.apply(&mut user1).unwrap();
    change3.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    change0.apply(&mut user2).unwrap();
    private_change2.apply(&mut user2).unwrap();
    change3.apply(&mut user2).unwrap();
    user2.commit().unwrap();

    change0.apply(&mut user3).unwrap();
    change2.apply(&mut user3).unwrap();
    private_change3.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    assert_eq!(user0.get_upstream_art().get_root_public_key(), new_root);
    assert_eq!(user1.get_upstream_art().get_root_public_key(), new_root);
    assert_eq!(user2.get_upstream_art().get_root_public_key(), new_root);
    assert_eq!(user3.get_upstream_art().get_root_public_key(), new_root);

    // Now all the participants have the same view on the state of the art
    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);
}

fn example_of_aggregation_usage() {
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
    let mut zero_art0 = PrivateZeroArt::new(art0, Box::new(thread_rng())).unwrap();

    // Create default aggregation
    let mut agg = AggregationContext::from_private_zero_art(&zero_art0, Box::new(thread_rng()));

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
    agg.apply(&mut zero_art0).unwrap();
    plain_agg.apply(&mut art1).unwrap();

    assert_eq!(agg.get_operation_tree(), &art1);
    assert_eq!(
        zero_art0.get_upstream_art().get_public_art(),
        art1.get_public_art()
    );
    assert_eq!(
        zero_art0.get_upstream_art().get_root_secret_key(),
        art1.get_root_secret_key()
    );
}

fn main() {
    example_of_simple_flow();
    example_of_merging_concurrent_changes();
    example_of_aggregation_usage();
}
