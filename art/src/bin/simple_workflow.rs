use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use bulletproofs::PedersenGens;
use cortado::{ALT_GENERATOR_X, ALT_GENERATOR_Y, CortadoAffine, Fr};
use postcard::{from_bytes, to_allocvec};
use std::ops::Mul;
use tracing::debug;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;
use zrt_art::TreeMethods;
use zrt_art::art::art_advanced_operations::ArtAdvancedOps;
use zrt_art::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt};
use zrt_art::changes::ApplicableChange;
use zrt_art::changes::VerifiableChange;
use zrt_art::changes::aggregations::{PlainChangeAggregation, ProverChangeAggregation};
use zrt_art::changes::branch_change::MergeBranchChange;
use zrt_art::node_index::NodeIndex;
use zrt_zk::aggregated_art::{
    ProverAggregationTree, VerifierAggregationTree, art_aggregated_prove, art_aggregated_verify,
};
use zrt_zk::art::{art_prove, art_verify};

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
    let mut zero_art_rng = thread_rng();
    let zero_art = PrivateZeroArt::new(art.clone(), &mut zero_art_rng);

    // PrivateArt implements Serialize and Deserialize, however there is a default implementation
    // for serialization with postcard. It will return bytes for serialized PublicART, which
    // doesn't contain any secret keys.
    let encoded_representation = to_allocvec(&art.get_public_art()).unwrap();
    // The deserialization method requires leaf secret key, as the encoded_representation is
    // the encoding of PrivateArt.
    let public_art: PublicArt<CortadoAffine> = from_bytes(&encoded_representation).unwrap();
    let recovered_private_art = PrivateArt::new(public_art.clone(), secrets[0]).unwrap();
    let mut recovered_art_rng = thread_rng();
    let recovered_art = PrivateZeroArt::new(recovered_private_art, &mut recovered_art_rng);

    assert_eq!(recovered_art, zero_art);

    // Assume art_i is i-th user art, which also knows i-th secret key.
    let mut art_0_rng = thread_rng();
    let mut art_0 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[0]).unwrap(),
        &mut art_0_rng,
    );
    let mut art_1_rng = thread_rng();
    let mut art_1 = PrivateZeroArt::new(
        PrivateArt::new(public_art.clone(), secrets[1]).unwrap(),
        &mut art_1_rng,
    );
    let new_secret_key_1 = Fr::rand(&mut rng);

    // Any user can update his public art with the next method.
    let change_1 = art_1.update_key(new_secret_key_1, None, &[]).unwrap();
    // Root key tk is a new common secret. Other users can use returned change to update
    // theirs trees. Fot example, it can be done as next:
    change_1.update(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // To get common secret, user can call the next method.
    let retrieved_tk_1 = art_0.get_root_secret_key().unwrap();

    // Other art modifications include addition and blanking.
    // Addition of a new node can be done as next:
    let new_node1_secret_key = Fr::rand(&mut rng);
    let changes_2 = art_1.add_member(new_node1_secret_key, None, &[]).unwrap();
    changes_2.update(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // Remove member from the tree, by making his node temporary.
    let new_node1_public_key = generator.mul(new_node1_secret_key).into_affine();
    let some_secret_key1 = Fr::rand(&mut rng);
    let target_node_path = art_1
        .get_public_art()
        .get_path_to_leaf_with(new_node1_public_key)
        .unwrap();
    let target_node_index = NodeIndex::from(target_node_path);
    let changes_3 = art_1
        .remove_member(&target_node_index, some_secret_key1, None, &[])
        .unwrap();
    changes_3.update(&mut art_0).unwrap();
    assert_eq!(art_0, art_1);

    // For proof generation, use `ProverArtefacts` structure. They are returned with every art update.
    // Let's prove key update:
    let associated_data = b"associated data";
    let some_secret_key4 = Fr::rand(&mut rng);
    let changes_4 = art_1
        .update_key(some_secret_key4, None, associated_data)
        .unwrap();

    let verification_result = changes_4.verify(
        &art_0,
        associated_data,
        vec![
            art_0
                .get_node(art_1.get_node_index())
                .unwrap()
                .get_public_key(),
        ],
    );

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );

    assert!(verification_result.is_ok());
}

fn merge_conflict_changes() {
    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let art0 = PrivateArt::setup(&secrets).unwrap();

    // Serialise and deserialize art for the other users.
    let public_art = art0.get_public_art().clone();

    // Store the basic art1.
    let art1: PrivateArt<CortadoAffine> = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

    // Create new users arts
    let mut user0 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[0]).unwrap();
    let mut user2 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[2]).unwrap();
    let mut user3 = PrivateArt::<CortadoAffine>::new(public_art.clone(), secrets[8]).unwrap();

    let sk0 = Fr::rand(&mut rng);
    let change0 = user0.update_key(sk0, None, &[]).unwrap();

    let sk2 = Fr::rand(&mut rng);
    let change2 = user2.update_key(sk2, None, &[]).unwrap();

    let sk3 = Fr::rand(&mut rng);
    let change3 = user3.update_key(sk3, None, &[]).unwrap();

    let applied_change = change0.clone();
    let all_but_0_changes = vec![change2.clone(), change3.clone()];
    let all_changes = vec![change0, change2, change3];

    // Merge for users which participated in the merge
    let mut participant = user0.clone();
    let participant_merge_change = MergeBranchChange::new_for_participant(
        art0.clone(),
        applied_change.clone(),
        all_but_0_changes.clone(),
    );
    participant_merge_change.update(&mut participant).unwrap();
    // participant
    //     .merge_for_participant(applied_change.clone(), &all_but_0_changes, art0.clone())
    //     .unwrap();

    // Merge for users which only observed the merge conflict
    let mut observer = art1.clone();
    let observer_merge_change = MergeBranchChange::new_for_observer(all_changes);
    observer_merge_change.update(&mut observer).unwrap();
    // observer.merge_for_observer(&all_changes).unwrap();

    assert_eq!(
        participant, observer,
        "Observer and participant have the same view on the state of the art."
    );
}

fn branch_aggregation_proof_verify() {
    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let mut art0 = PrivateArt::setup(&secrets).unwrap();

    let mut art1 =
        PrivateArt::<CortadoAffine>::new(art0.get_public_art().clone(), secrets[1]).unwrap();

    let target_3 = art0
        .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();

    let mut zero_art0_rng = thread_rng();
    let mut zero_art0 = PrivateZeroArt::new(art0, &mut zero_art0_rng);

    // Create default aggregation
    let mut agg = ProverChangeAggregation::default();

    // Perform some changes
    agg.add_member(Fr::rand(&mut rng), &mut zero_art0).unwrap();
    agg.remove_member(&target_3, Fr::rand(&mut rng), &mut zero_art0)
        .unwrap();
    agg.add_member(Fr::rand(&mut rng), &mut zero_art0).unwrap();
    agg.leave(Fr::rand(&mut rng), &mut zero_art0).unwrap();

    // Gather associated data
    let associated_data = b"associated data";

    let verifiable_agg = agg.prove(&zero_art0, associated_data).unwrap();

    let aux_pk = zero_art0.get_leaf_public_key().unwrap();
    verifiable_agg
        .verify(&zero_art0, associated_data, vec![aux_pk])
        .unwrap();

    // Finally update private art with the `extracted_agg` aggregation.
    verifiable_agg.update(&mut art1).unwrap();

    assert_eq!(zero_art0.get_public_art(), art1.get_public_art());
    assert_eq!(
        zero_art0.get_root_secret_key().unwrap(),
        art1.get_root_secret_key().unwrap()
    );
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
    let mut agg = PlainChangeAggregation::default();

    // Perform some changes
    agg.add_member(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.remove_member(&target_3, Fr::rand(&mut rng), &mut art0)
        .unwrap();
    agg.update_key(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.add_member(Fr::rand(&mut rng), &mut art0).unwrap();
    agg.leave(Fr::rand(&mut rng), &mut art0).unwrap();

    // Finally update private art with the `agg` plain aggregation.
    agg.update(&mut art1).unwrap();

    assert_eq!(art0.get_public_art(), art1.get_public_art());
    assert_eq!(
        art0.get_root_secret_key().unwrap(),
        art1.get_root_secret_key().unwrap()
    );
}

fn main() {
    general_example();
    merge_conflict_changes();
    branch_aggregation_proof_verify();
    branch_aggregation();
}
