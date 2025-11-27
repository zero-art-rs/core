use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use cortado::{CortadoAffine, Fr};
use postcard::{from_bytes, to_allocvec};
use std::ops::Mul;
use ark_serialize::CanonicalSerialize;
use zrt_art::art::{AggregationContext, ArtAdvancedOps, PrivateArt, PublicArt};
use zrt_art::art_node::TreeMethods;
use zrt_art::changes::aggregations::AggregatedChange;
use zrt_art::changes::ApplicableChange;
use zrt_art::changes::branch_change::{BranchChange, PrivateBranchChange};
use zrt_art::node_index::NodeIndex;
use zrt_zk::engine::{ZeroArtProverEngine, ZeroArtVerifierEngine};
use zrt_zk::{EligibilityArtefact, EligibilityRequirement};
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};

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

    // For new art, creator provides the next method with set of members secrets.
    let art = PrivateArt::setup(&secrets).unwrap();

    // PublicArt implements Derive for serialization. For example one can serialize public art as next:
    let encoded_representation = to_allocvec(art.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&encoded_representation).unwrap();

    // When rhe user receives his art, he can derive a new PrivateArt with his leaf secret key.
    let recovered_art = PrivateArt::new(public_art.clone(), secrets[0]).unwrap();

    assert_eq!(recovered_art, art);

    // For example, assume art_i is i-th user art, which also knows i-th secret key.
    let mut art_0 = PrivateArt::new(public_art.clone(), secrets[0]).unwrap();

    let mut art_1 = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

    let new_secret_key_1 = Fr::rand(&mut rng);

    // Any user can update his public art with the next method.
    let (_, output_1) = art_1.update_key(new_secret_key_1).unwrap();
    // Apply ephemeral operation to the ART tree with private branch change.
    new_secret_key_1.apply(&mut art_1).unwrap();
    // Commit applied operation.
    art_1.commit().unwrap();

    // Retrieve change from the private branch change
    let change_1 = BranchChange::from(output_1);

    // Root key tk is a new common secret. To get common secret, user should use the next method.
    let _retrieved_tk_1 = art_0.root_secret_key();

    // Other users can use returned change to update local tree. Fot example, this can be done as next:
    change_1.apply(&mut art_0).unwrap();
    art_0.commit().unwrap();
    assert_eq!(art_0, art_1);

    // Other art modifications include addition and blanking.
    // Addition of a new node can be done as next:
    let new_node1_secret_key = Fr::rand(&mut rng);
    let (_, change_2) = art_1.add_member(new_node1_secret_key).unwrap();

    change_2.apply(&mut art_0).unwrap();
    art_0.commit().unwrap();
    change_2.apply(&mut art_1).unwrap();
    art_1.commit().unwrap();
    assert_eq!(art_0, art_1);

    // Remove member from the tree, by making his node temporary.
    let new_node1_public_key = generator.mul(new_node1_secret_key).into_affine();
    let some_secret_key1 = Fr::rand(&mut rng);
    let target_node_path = art_1
        .root()
        .path_to_leaf_with(new_node1_public_key)
        .unwrap();

    let target_node_index = NodeIndex::from(target_node_path);
    let (_, output_3) = art_1
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
    let (_, changes_4, prover_branch_4) = art_1.update_key(some_secret_key4).unwrap();

    // For proof creation one can use prover engine.
    let prover_engine = ZeroArtProverEngine::default();
    // Create context, and provide it with required data.
    let proof = prover_engine
        .new_context(EligibilityArtefact::Member((
            art_1.leaf_secret_key(),
            art_1.leaf_public_key(),
        )))
        .for_branch(&prover_branch_4)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    // On the other hand, for verification one can use verifier engine with verifier context
    let verifier_engine = ZeroArtVerifierEngine::default();
    // To verify the change, one eligibility_requirement should be passed as with proof creation.
    let eligibility_requirement = EligibilityRequirement::Member(
        art_0
            .root()
            .node(&changes_4.node_index)
            .unwrap()
            .public_key(),
    );
    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&art_0.verification_branch(&changes_4).unwrap())
        .verify(&proof);

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

    let creator_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let public_art = creator_art.public_art().clone();

    // Create new users arts
    let mut user0 = creator_art;
    let mut user1 = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();
    let mut user2 = PrivateArt::new(public_art.clone(), secrets[2]).unwrap();
    let mut user3 = PrivateArt::new(public_art.clone(), secrets[8]).unwrap();

    // Create some concurrent changes
    let sk0 = Fr::rand(&mut rng);
    let (_, change0) = user0.update_key(sk0).unwrap();

    let sk2 = Fr::rand(&mut rng);
    let (_, change2) = user2.update_key(sk2).unwrap();

    let sk3 = Fr::rand(&mut rng);
    let (_, change3) = user3.update_key(sk3).unwrap();

    let new_root = *change0.public_keys.first().unwrap()
        + *change2.public_keys.first().unwrap()
        + *change3.public_keys.first().unwrap();
    let new_root = new_root.into_affine();

    // Apply changes to ART trees. Use private_change to apply change of the user own key.
    // Every application returns partial root secret, i.e. the one, provided with the
    // change itself.
    let tk11 = sk0.apply(&mut user0).unwrap();
    let tk21 = change2.apply(&mut user0).unwrap();
    let tk31 = change3.apply(&mut user0).unwrap();
    user0.commit().unwrap();
    assert_eq!(tk11 + tk21 + tk31, user0.root_secret_key());

    let tk12 = change0.apply(&mut user1).unwrap();
    let tk22 = change2.apply(&mut user1).unwrap();
    let tk32 = change3.apply(&mut user1).unwrap();
    user1.commit().unwrap();
    assert_eq!(tk12 + tk22 + tk32, user1.root_secret_key());

    let tk13 = change0.apply(&mut user2).unwrap();
    let tk23 = sk2.apply(&mut user2).unwrap();
    let tk33 = change3.apply(&mut user2).unwrap();
    user2.commit().unwrap();
    assert_eq!(tk13 + tk23 + tk33, user2.root_secret_key());

    let tk14 = change0.apply(&mut user3).unwrap();
    let tk24 = change2.apply(&mut user3).unwrap();
    let tk34 = sk3.apply(&mut user3).unwrap();
    user3.commit().unwrap();
    assert_eq!(tk14 + tk24 + tk34, user3.root_secret_key());

    assert_eq!(user0.root_public_key(), new_root);
    assert_eq!(user1.root_public_key(), new_root);
    assert_eq!(user2.root_public_key(), new_root);
    assert_eq!(user3.root_public_key(), new_root);

    // Now all the participants have the same view on the state of the art
    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);
}

fn example_of_aggregation_usage() {
    // Create default prover and verifier engines for proof creation and verification.
    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secrets: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
    let mut user0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

    // Create a different user.
    let mut user1 = PrivateArt::new(user0.public_art().clone(), secrets[1]).unwrap();

    // Define some target user, to be removed.
    let target_3 = user0
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    let target_3_index = NodeIndex::from(target_3);

    // Create default aggregation
    let mut agg = AggregationContext::from(user0.clone());

    // Perform some changes
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.remove_member(&target_3_index, Fr::rand(&mut rng))
        .unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.leave_group(Fr::rand(&mut rng)).unwrap();

    // Gather associated data
    let associated_data = b"associated data";

    // Create verifiable aggregation.
    let eligibility_artefact = EligibilityArtefact::Owner((user0.leaf_secret_key(), user0.leaf_public_key()));
    let proof = prover_engine
        .new_context(eligibility_artefact)
        .for_aggregation(&ProverAggregationTree::try_from(&agg).unwrap())
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let change = AggregatedChange::try_from(&agg).unwrap();

    // Aggregation verification is similar to usual change aggregation.
    let aux_pk = user0.leaf_public_key();
    let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
    let verifier_artefacts = change.add_co_path(user0.public_art()).unwrap();
    let verifier_tree = VerifierAggregationTree::try_from(&verifier_artefacts).unwrap();
    verifier_engine
        .new_context(eligibility_requirement)
        .for_aggregation(&verifier_tree)
        .with_associated_data(associated_data)
        .verify(&proof)
        .unwrap();

    // Finally update private art with the `change` aggregation. Note, that we cant update
    // user0 in usual means, because his secret key changed.
    user0 = PrivateArt::from(agg.clone());
    change.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    assert_eq!(agg.operation_tree(), &user1);
    assert_eq!(
        user0.public_art(),
        user1.public_art()
    );
    assert_eq!(
        user0.root_secret_key(),
        user1.root_secret_key()
    );
}

fn main() {
    example_of_simple_flow();
    example_of_merging_concurrent_changes();
    example_of_aggregation_usage();
}
