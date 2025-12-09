use crate::art::private_art::ArtSecrets;
use crate::art::{ArtAdvancedOps, PrivateArt, PublicArt};
use crate::art_node::{LeafStatus, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::branch_change::{BranchChange, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::{Direction, NodeIndex};
use crate::test_helper_tools::init_tracing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{Rng, SeedableRng, thread_rng};
use cortado::{CortadoAffine, Fr};
use itertools::Itertools;
use postcard::{from_bytes, to_allocvec};
use rand::random;
use std::cell::{Cell, Ref, RefCell};
use std::cmp::{max, min};
use std::ops::{Add, DerefMut, Mul};
use tracing::{debug, error, info, trace, warn};
use zrt_zk::art::ArtProof;
use zrt_zk::engine::{ZeroArtProverEngine, ZeroArtVerifierEngine};
use zrt_zk::{EligibilityArtefact, EligibilityRequirement};

const TEST_GROUP_SIZE: usize = 20;

#[test]
/// Test if art serialization -> deserialization works correctly for unchanged arts
fn test_public_art_initial_serialization() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);

    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    for i in (1..TEST_GROUP_SIZE).step_by(7) {
        let private_art = PrivateArt::setup(&secrets[..i]).unwrap();
        let public_art_bytes = to_allocvec(&private_art.public_art()).unwrap();

        // Try to deserialize art for every other user in a group
        for j in 0..i {
            let deserialized_art: PrivateArt<CortadoAffine> =
                PrivateArt::new(from_bytes(&public_art_bytes).unwrap(), secrets[j]).unwrap();

            assert_eq!(
                deserialized_art,
                private_art,
                "Both users have the same view on the state of the art (size: {i}, user: {j}). Deserialized_art:\n{}\nPrivate_art\n{}\n\
                    deserialized_art.secrets: {:#?},\nprivate_art.secrets: {:#?}\n\
                    deserialized_art.leaf_secret: {:?},\nprivate_art.leaf_secret: {:?}",
                deserialized_art.root(),
                private_art.root(),
                deserialized_art.secrets,
                private_art.secrets,
                secrets[0],
                secrets[j]
            );
        }
    }
}

#[test]
fn test_art_weight_balance_at_creation() {
    for i in 1..TEST_GROUP_SIZE {
        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..i).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();
        let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

        let mut min_height = u64::MAX;
        let mut max_height = u64::MIN;
        let root = art.root();

        for (_, path) in root.leaf_iter_with_path() {
            min_height = min(min_height, path.len() as u64);
            max_height = max(max_height, path.len() as u64);
        }

        assert!(max_height - min_height < 2);
    }
}

#[test]
fn test_flow_append_join_update() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);

    let mut user0 = PrivateArt::setup(&vec![secret_key_0]).unwrap();
    assert_eq!(
        user0.leaf_public_key(),
        CortadoAffine::generator().mul(secret_key_0).into_affine(),
        "New node is in the art, and it is on the correct path.",
    );

    // Add member with user0
    let secret_key_1 = Fr::rand(&mut rng);
    assert_ne!(secret_key_0, secret_key_1);
    let (_, change0) = user0.add_member(secret_key_1).unwrap();

    verify_secrets_are_correct(&user0).unwrap();

    let tk = change0.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    verify_secrets_are_correct(&user0).unwrap();

    assert_eq!(user0.leaf_secret_key(), secret_key_0);
    assert_eq!(
        user0
            .node(&change0.node_index)
            .unwrap()
            .child(Direction::Right)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator().mul(secret_key_1).into_affine(),
        "New node is in the art, and it is on the correct path.",
    );
    assert_eq!(
        user0.node(&user0.node_index()).unwrap().data().public_key(),
        CortadoAffine::generator().mul(secret_key_0).into_affine(),
        "User node is isn't changed, after append member operation.",
    );
    assert_ne!(
        user0.node(&change0.node_index).unwrap().data().public_key(),
        user0.node(&user0.node_index()).unwrap().data().public_key(),
        "Sanity check: Both users nodes have different public key.",
    );

    // Serialise and deserialize art for the new user.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    assert_ne!(secret_key_0, secret_key_1);
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    assert_eq!(public_art.root(), user0.root());

    let mut user1 = PrivateArt::new(public_art, secret_key_1).unwrap();
    assert_eq!(user1.leaf_secret_key(), secret_key_1);
    assert_eq!(user1.root_secret_key(), user0.root_secret_key());
    // info!("user1\n{}", user1.root());

    assert_ne!(
        user0.secrets, user1.secrets,
        "Sanity check: Both users have different path secrets"
    );
    assert_eq!(user0.root(), user1.root());
    assert_eq!(user0.root_secret_key(), user1.root_secret_key());
    assert!(user0.eq(&user1), "New user received the same art");
    assert_eq!(
        user0, user1,
        "Both users have the same view on the state of the art"
    );

    let tk0 = user0.root_secret_key();
    let tk1 = user1.root_secret_key();

    let secret_key_3 = Fr::rand(&mut rng);

    // New user updates his key
    assert_ne!(secret_key_1, secret_key_3);
    let (tk2, change_key_update) = user1.update_key(secret_key_3).unwrap();
    // user1.apply(&change_key_update).unwrap();
    user1.apply(&secret_key_3).unwrap();
    user1.commit().unwrap();
    assert_eq!(user1.leaf_secret_key(), secret_key_3);

    let tk2 = user1.root_secret_key();
    assert_ne!(
        tk1,
        user1.root_secret_key(),
        "Sanity check: old tk is different from the stored one."
    );
    assert_ne!(
        user0, user1,
        "Both users have different view on the state of the art, as they are not synced yet"
    );
    assert_eq!(user1.leaf_secret_key(), secret_key_3,);

    let tk = change_key_update.apply(&mut user0).unwrap();
    user0.commit().unwrap();
    assert_eq!(user0.root(), user1.root());
    assert_eq!(user0.root_secret_key(), user1.root_secret_key());
    assert_eq!(
        user0
            .root()
            .child(Direction::Right)
            .unwrap()
            .data()
            .public_key(),
        user1.leaf_public_key(),
    );

    assert_eq!(
        user0, user1,
        "Both users have the same view on the state of the art"
    );
    assert_ne!(
        tk2, tk1,
        "Sanity check: old tk is different from the new one."
    );

    verify_secrets_are_correct(&user0).unwrap();
    verify_secrets_are_correct(&user1).unwrap();
}

#[test]
fn test_root_retrieval_correctness_after_update() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);

    let mut user0 = PrivateArt::setup(&vec![secret_key_0]).unwrap();
    assert_eq!(
        user0.leaf_public_key(),
        CortadoAffine::generator().mul(secret_key_0).into_affine(),
        "New node is in the art, and it is on the correct path.",
    );

    // Add member with user0
    let secret_key_1 = Fr::rand(&mut rng);
    assert_ne!(secret_key_0, secret_key_1);
    let (_, change0) = user0.add_member(secret_key_1).unwrap();


    verify_secrets_are_correct(&user0).unwrap();
    let tk = change0.apply(&mut user0).unwrap();
    let tree_key  = user0.secrets().preview().root();
    let tree_public_key  = user0.preview().root().public_key();
    let real_public_key = CortadoAffine::generator().mul(tree_key).into_affine();
    assert_eq!(tree_public_key, real_public_key);
    verify_secrets_are_correct(&user0).unwrap();
}

// /// Test flow
// #[test]
// fn test_flow_join_update_update() {
//
// }

/// Creator, after computing the art with several users, removes the target_user. The
/// remaining users updates their art, and one of them, also removes target_user (instead
/// or changing, he merges two updates). Removed user fails to update his art.
#[test]
fn test_removal_of_the_same_user() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);
    let secret_key_1 = Fr::rand(&mut rng);
    let secret_key_2 = Fr::rand(&mut rng);
    let secret_key_3 = Fr::rand(&mut rng);

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
        secret_key_0,
        secret_key_1,
        secret_key_2,
        secret_key_3,
    ])
    .unwrap();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    let mut user1: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

    let mut user2: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

    let mut user3: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

    assert!(user0.eq(&user1), "New user received the same art");
    assert!(user0.eq(&user2), "New user received the same art");
    assert!(user0.eq(&user3), "New user received the same art");

    let tk0 = user0.root_secret_key();
    let tk1 = user1.root_secret_key();
    let tk2 = user2.root_secret_key();
    let tk3 = user2.root_secret_key();

    let blanking_secret_key_1 = Fr::rand(&mut rng);
    let blanking_secret_key_2 = Fr::rand(&mut rng);

    // User0 removes second user node from the art.
    let (tk, remove_member_change1) = user0
        .remove_member(&user2.node_index(), blanking_secret_key_1)
        .unwrap();

    remove_member_change1.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    let tk_r1 = user0.root_secret_key();
    assert_ne!(
        tk1, tk_r1,
        "Sanity check: old tk is different from the stored one."
    );
    assert_ne!(
        user0, user1,
        "Both users have different view on the state of the art, as they are not synced yet."
    );
    assert_ne!(
        user0, user2,
        "Both users have different view on the state of the art, as they are not synced yet."
    );
    assert_eq!(
        user0
            .public_art()
            .node(&remove_member_change1.node_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(blanking_secret_key_1)
            .into_affine(),
        "The node was removed correctly."
    );

    // Sync other users art
    remove_member_change1.apply(&mut user1).unwrap();
    user1.commit().unwrap();
    remove_member_change1.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    let err = remove_member_change1.apply(&mut user2).err();
    assert!(
        matches!(err, Some(ArtError::InapplicableBlanking)),
        "Must fail to perform art update using blank leaf, but got {:?}.",
        err
    );

    assert_eq!(
        user0,
        user1,
        "Both users have the same view on the state of the art, but have: user0:\n{},\nuser1:\n{}",
        user0.root(),
        user1.root(),
    );
    assert_eq!(
        user0, user3,
        "Both users have the same view on the state of the art"
    );
    assert_eq!(
        user1
            .public_art()
            .node(&remove_member_change1.node_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(blanking_secret_key_1)
            .into_affine(),
        "The node was removed correctly."
    );

    // User1 removes second user node from the art.
    let (tk, remove_member_change2) = user1
        .remove_member(&user2.node_index(), blanking_secret_key_2)
        .unwrap();
    user1.apply(&remove_member_change2).unwrap();
    user1.commit().unwrap();

    let tk_r2 = user1.root_secret_key();
    assert_eq!(
        user1
            .public_art()
            .node(&remove_member_change2.node_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(blanking_secret_key_1 + blanking_secret_key_2)
            .into_affine(),
        "The node was removed correctly."
    );
    assert_eq!(
        user1.root().data().public_key(),
        CortadoAffine::generator().mul(tk_r2).into_affine(),
        "The node was removed correctly."
    );
    assert_ne!(
        tk_r1, tk_r2,
        "Sanity check: old tk is different from the new one."
    );
    assert_eq!(
        tk_r2,
        user1.root_secret_key(),
        "Sanity check: new tk is the same as the stored one."
    );
    assert_ne!(
        user0, user1,
        "Both users have different view on the state of the art, as they are not synced yet."
    );
    assert_ne!(
        user1, user2,
        "Both users have different view on the state of the art, as they are not synced yet."
    );

    // Sync other users art
    remove_member_change2.apply(&mut user0).unwrap();
    user0.commit().unwrap();
    remove_member_change2.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    assert_eq!(
        user0.root_secret_key(),
        user1.root_secret_key(),
        "Both users have the same view on the state of the art"
    );

    assert_eq!(
        user0, user1,
        "Both users have the same view on the state of the art"
    );
    assert_eq!(
        user0, user3,
        "Both users have the same view on the state of the art"
    );
    assert_eq!(
        user1
            .public_art()
            .node(&remove_member_change1.node_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(blanking_secret_key_1 + blanking_secret_key_2)
            .into_affine(),
        "The node was removed correctly."
    );
}

#[test]
fn test_art_key_update() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);
    let main_user_id = 0;
    let test_user_id = 12;
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art.clone();

    let mut users_arts = Vec::new();
    for i in 0..TEST_GROUP_SIZE {
        users_arts.push(PrivateArt::new(public_art.clone(), secrets[i]).unwrap());
    }

    let root_key = private_art.root_secret_key();
    for i in 0..TEST_GROUP_SIZE {
        // Assert creator and users computed the same tree key.
        assert_eq!(users_arts[i].root_secret_key(), root_key);
        verify_secrets_are_correct(&users_arts[i]).unwrap();
    }

    // Save old secret key to roll back
    let main_old_key = secrets[main_user_id];
    let main_new_key = Fr::rand(&mut rng);
    let (tk, change) = users_arts[main_user_id].update_key(main_new_key).unwrap();
    let changes = PrivateBranchChange::new(main_new_key, change);

    for i in 0..TEST_GROUP_SIZE {
        assert_eq!(users_arts[i].root(), public_art.root());
        changes.apply(&mut users_arts[i]).unwrap();
        users_arts[i].commit().unwrap();

        verify_secrets_are_correct(&users_arts[i]).unwrap();
        assert_eq!(
            users_arts[i].root(),
            users_arts[0].root(),
            "Art trees of user {i} and user 0 are different. users_arts[i]:\n{},\nwhen user0:\n{}",
            users_arts[i].root(),
            users_arts[0].root()
        );
        assert_eq!(
            users_arts[i].root_secret_key(),
            users_arts[0].root_secret_key()
        );
        assert_eq!(
            users_arts[i].root_secret_key(),
            tk,
            "users_arts[i]:\n{},\nwhen user0:\n{}",
            users_arts[i].root(),
            users_arts[0].root()
        );
    }

    assert_ne!(users_arts[main_user_id].leaf_secret_key(), main_old_key);

    let mut parent = users_arts[main_user_id].root();
    let mut pub_keys = vec![parent.data().public_key()];
    for direction in &users_arts[main_user_id].node_index().get_path().unwrap() {
        pub_keys.push(parent.child(*direction).unwrap().data().public_key());
        parent = parent.child(*direction).unwrap();
    }

    for (secret_key, corr_pk) in users_arts[main_user_id]
        .secrets
        .secrets()
        .iter()
        .zip(pub_keys.iter())
    {
        assert_eq!(
            CortadoAffine::generator().mul(secret_key).into_affine(),
            *corr_pk,
            "Multiplication done correctly."
        );
    }

    changes.apply(&mut users_arts[test_user_id]).unwrap();
    users_arts[test_user_id].commit().unwrap();

    let new_key = users_arts[main_user_id].root_secret_key();
    assert_eq!(
        users_arts[test_user_id].root(),
        users_arts[main_user_id].root()
    );
    assert_eq!(
        users_arts[test_user_id].root_secret_key(),
        users_arts[main_user_id].root_secret_key()
    );
    assert_eq!(users_arts[test_user_id].root_secret_key(), new_key);

    let (tk, change) = users_arts[main_user_id].update_key(main_old_key).unwrap();
    let changes = PrivateBranchChange::new(main_old_key, change);

    for i in 0..TEST_GROUP_SIZE {
        changes.apply(&mut users_arts[i]).unwrap();
        users_arts[i].commit().unwrap();
        assert_eq!(users_arts[i].root_secret_key(), tk);
    }

    let recomputed_old_key = users_arts[main_user_id].root_secret_key();
    assert_eq!(tk, recomputed_old_key);
    assert_eq!(root_key, recomputed_old_key);

    for i in 0..TEST_GROUP_SIZE as usize {
        changes.apply(&mut users_arts[i]).unwrap();
        users_arts[i].commit().unwrap();
        assert_eq!(users_arts[i].root_secret_key(), recomputed_old_key);
    }
}

#[test]
fn test_add_member_weight_correctness() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);
    let main_user_id = 0;
    let test_user_id = 12;
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let mut private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

    let user_secret = private_art.leaf_secret_key();
    let user_public_key = private_art.leaf_public_key();

    assert_eq!(user_secret, private_art.leaf_secret_key());

    for i in 0..100 {
        let (_, change, _) = private_art.add_member(Fr::rand(&mut rng)).unwrap();
        change.apply(&mut private_art).unwrap();

        assert_eq!(user_secret, private_art.leaf_secret_key());
        assert_eq!(
            private_art
                .node(private_art.node_index())
                .unwrap()
                .data()
                .public_key(),
            user_public_key
        );

        private_art.commit().unwrap();

        assert_eq!(user_secret, private_art.leaf_secret_key());
        assert_eq!(
            private_art
                .node(private_art.node_index())
                .unwrap()
                .data()
                .public_key(),
            user_public_key
        );

        for node in private_art.root() {
            if node.is_leaf() {
                if !matches!(node.data().status(), Some(LeafStatus::Active)) {
                    assert_eq!(node.data().weight(), 0);
                } else {
                    assert_eq!(node.data().weight(), 1);
                }
            } else {
                assert_eq!(
                    node.data().weight(),
                    node.child(Direction::Left).unwrap().data().weight()
                        + node.child(Direction::Right).unwrap().data().weight(),
                    "private_art:\n{}",
                    private_art.root()
                );
            }
        }
    }
}

/// Main user creates art with four users, then first, second, and third users updates their
/// arts. The forth user, applies changes, but swaps first two.
#[test]
fn test_wrong_changes_commit_ordering() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);
    let secret_key_1 = Fr::rand(&mut rng);
    let secret_key_2 = Fr::rand(&mut rng);
    let secret_key_3 = Fr::rand(&mut rng);
    assert_ne!(secret_key_0, secret_key_1);
    assert_ne!(secret_key_1, secret_key_2);
    assert_ne!(secret_key_2, secret_key_3);

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
        secret_key_0,
        secret_key_1,
        secret_key_2,
        secret_key_3,
    ])
    .unwrap();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    let mut user1: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

    let mut user2: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

    let mut user3: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

    // User0 updates his key.
    let new_sk0 = Fr::rand(&mut rng);
    let (tk0, key_update_change0) = user0.update_key(new_sk0).unwrap();
    user0.apply(&new_sk0).unwrap();
    user0.commit().unwrap();
    let tk_r0 = user0.root_secret_key();

    // User1 updates his art.
    key_update_change0.apply(&mut user1).unwrap();
    user1.commit().unwrap();
    let new_sk1 = Fr::rand(&mut rng);
    let (tk1, key_update_change1) = user1.update_key(new_sk1).unwrap();
    new_sk1.apply(&mut user1).unwrap();
    user1.commit().unwrap();
    let tk_r1 = user1.root_secret_key();
    assert_eq!(
        tk_r1,
        user1.root_secret_key(),
        "Sanity check: new tk is the same as the stored one."
    );

    // User2 updates his art.
    key_update_change0.apply(&mut user2).unwrap();
    user2.commit().unwrap();
    key_update_change1.apply(&mut user2).unwrap();
    user2.commit().unwrap();
    let new_sk2 = Fr::rand(&mut rng);
    let (tk2, key_update_change2) = user2.update_key(new_sk2).unwrap();
    new_sk2.apply(&mut user2).unwrap();
    user2.commit().unwrap();
    let tk_r2 = user2.root_secret_key();
    assert_eq!(
        tk_r2,
        user2.root_secret_key(),
        "Sanity check: new tk is the same as the stored one."
    );

    // Update art for other users.
    key_update_change1.apply(&mut user3).unwrap();
    user3.commit().unwrap();
    key_update_change0.apply(&mut user3).unwrap();
    user3.commit().unwrap();
    key_update_change2.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    assert_ne!(
        user3.root(),
        user2.root(),
        "Wrong order of updates will bring to different public arts."
    );
}

/// The same key update, shouldn't affect the art, as it will be overwritten by itself.
#[test]
fn test_apply_key_update_changes_twice() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secret_key_0 = Fr::rand(&mut rng);
    let secret_key_1 = Fr::rand(&mut rng);
    let secret_key_2 = Fr::rand(&mut rng);
    let secret_key_3 = Fr::rand(&mut rng);
    assert_ne!(secret_key_0, secret_key_1);

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
        secret_key_0,
        secret_key_1,
        secret_key_2,
        secret_key_3,
    ])
    .unwrap();
    let def_tk = user0.root_secret_key();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    let mut user1: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

    // User0 updates his key.
    let new_sk0 = Fr::rand(&mut rng);
    let (_, key_update_change0) = user0.update_key(new_sk0).unwrap();

    // Update art for other users.
    key_update_change0.apply(&mut user1).unwrap();
    key_update_change0.apply(&mut user1).unwrap();

    assert_eq!(
        user0, user1,
        "Applying of the same key update twice, will give no affect."
    );
}

#[test]
fn test_correctness_for_method_from() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);
    let secret_key_1 = Fr::rand(&mut rng);
    let secret_key_2 = Fr::rand(&mut rng);
    let secret_key_3 = Fr::rand(&mut rng);

    let user0 = PrivateArt::<CortadoAffine>::setup(&vec![
        secret_key_0,
        secret_key_1,
        secret_key_2,
        secret_key_3,
    ])
    .unwrap();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    let user1: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

    let user1_2 = PrivateArt::restore(
        public_art.clone(),
        ArtSecrets::try_from(user1.secrets.secrets().clone()).unwrap(),
    )
    .unwrap();

    assert_eq!(user1, user1_2);

    assert_eq!(user1.secrets, user1_2.secrets);
}

#[test]
fn test_get_node() {
    init_tracing();

    debug!("Some data");

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let leaf_secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let mut user0: PrivateArt<CortadoAffine> = PrivateArt::setup(&leaf_secrets).unwrap();

    let random_public_key = CortadoAffine::rand(&mut rng);
    assert!(user0.root().node_with(random_public_key).is_err());
    assert!(
        user0
            .public_art()
            .root()
            .leaf_with(random_public_key)
            .is_err()
    );

    for sk in &leaf_secrets {
        let pk = CortadoAffine::generator().mul(sk).into_affine();
        let leaf = user0.public_art().root().leaf_with(pk).unwrap();
        assert_eq!(leaf.data().public_key(), pk);
        assert!(leaf.is_leaf());
    }

    for sk in &leaf_secrets {
        let pk = CortadoAffine::generator().mul(sk).into_affine();
        let leaf = user0.public_art().root().node_with(pk).unwrap();
        assert_eq!(leaf.data().public_key(), pk);
    }

    for sk in &leaf_secrets {
        let pk = CortadoAffine::generator().mul(sk).into_affine();
        let leaf_path = user0.public_art().root().path_to_leaf_with(pk).unwrap();
        let leaf = user0
            .public_art()
            .node(&NodeIndex::Direction(leaf_path))
            .unwrap();
        assert_eq!(leaf.data().public_key(), pk);

        assert!(leaf.is_leaf());
    }
}

#[test]
fn test_apply_key_update_to_itself() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let secret_key_0 = Fr::rand(&mut rng);
    let secret_key_1 = Fr::rand(&mut rng);
    let secret_key_2 = Fr::rand(&mut rng);
    let secret_key_3 = Fr::rand(&mut rng);

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
        secret_key_0,
        secret_key_1,
        secret_key_2,
        secret_key_3,
    ])
    .unwrap();

    // Serialise and deserialize art for the other users.
    let public_art_bytes = to_allocvec(&user0.public_art()).unwrap();
    let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

    let mut user1: PrivateArt<CortadoAffine> =
        PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

    // User0 updates his key.
    let new_sk0 = Fr::rand(&mut rng);
    let (tk, key_update_change0) = user0.update_key(new_sk0).unwrap();

    // User1 fails to update his art.
    assert!(matches!(
        key_update_change0.apply(&mut user1),
        Err(ArtError::InapplicableKeyUpdate)
    ));
}

#[test]
fn test_art_weights_after_one_add_member() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let mut tree: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let mut rng = &mut StdRng::seed_from_u64(rand::random());

    for _ in 1..TEST_GROUP_SIZE {
        let (_, _, _) = tree.add_member(Fr::rand(&mut rng)).unwrap();
    }

    for node in tree.root() {
        if node.is_leaf() {
            if !matches!(node.data().status(), Some(LeafStatus::Active)) {
                assert_eq!(node.data().weight(), 0);
            } else {
                assert_eq!(node.data().weight(), 1);
            }
        } else {
            assert_eq!(
                node.data().weight(),
                node.child(Direction::Left).unwrap().data().weight()
                    + node.child(Direction::Right).unwrap().data().weight()
            );
        }
    }
}

#[test]
fn test_weights_correctness_for_make_blank() {
    init_tracing();
    let mut rng = StdRng::seed_from_u64(0);
    let secrets = (0..9).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let mut user0 = PrivateArt::setup(&secrets).unwrap();

    let target_user_path = user0
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    let target_user_index = NodeIndex::from(target_user_path);

    let (tk, change) = user0
        .remove_member(&target_user_index, Fr::rand(&mut rng))
        .unwrap();
    change.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    assert_eq!(user0.root().data().weight() + 1, secrets.len());

    for node in user0.root() {
        if node.is_leaf() {
            if !matches!(node.data().status(), Some(LeafStatus::Active)) {
                assert_eq!(node.data().weight(), 0);
            } else {
                assert_eq!(node.data().weight(), 1);
            }
        } else {
            assert_eq!(
                node.data().weight(),
                node.child(Direction::Left).unwrap().data().weight()
                    + node.child(Direction::Right).unwrap().data().weight()
            );
        }
    }
}

#[test]
fn test_leaf_status_affect_on_make_blank() {
    init_tracing();

    if TEST_GROUP_SIZE < 2 {
        warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
        return;
    }

    let seed = rand::random();
    let mut rng = StdRng::seed_from_u64(seed);
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();
    let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

    let sk_1 = Fr::rand(&mut rng);
    let sk_2 = Fr::rand(&mut rng);
    let user_2_path = art
        .public_art()
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(&secrets[1]).into_affine())
        .unwrap();
    let user_2_index = NodeIndex::from(user_2_path.clone());

    let mut art1 = art.clone();
    let (_, remove11) = art1.remove_member(&user_2_index, sk_1).unwrap();
    remove11.apply(&mut art1).unwrap();
    art1.commit().unwrap();
    let (_, remove12) = art1.remove_member(&user_2_index, sk_2).unwrap();
    remove12.apply(&mut art1).unwrap();
    art1.commit().unwrap();
    assert_eq!(
        art1.public_art()
            .node(&user_2_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
    );

    let mut art2 = art.clone();
    art2.public_art
        .mut_node(&user_2_index)
        .unwrap()
        .data
        .set_status(LeafStatus::PendingRemoval)
        .unwrap();
    let (_, remove21) = art2.remove_member(&user_2_index, sk_1).unwrap();
    remove21.apply(&mut art2).unwrap();
    art2.commit().unwrap();
    let (_, remove22) = art2.remove_member(&user_2_index, sk_2).unwrap();
    remove22.apply(&mut art2).unwrap();
    art2.commit().unwrap();

    assert_eq!(
        art2.public_art()
            .node(&user_2_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
    );

    let mut art3 = art.clone();
    art3.public_art
        .mut_node(&user_2_index)
        .unwrap()
        .data
        .set_status(LeafStatus::Blank)
        .unwrap();
    let (_, remove31) = art3.remove_member(&user_2_index, sk_1).unwrap();
    remove31.apply(&mut art3).unwrap();
    art3.commit().unwrap();
    let (_, remove32) = art3.remove_member(&user_2_index, sk_2).unwrap();
    remove32.apply(&mut art3).unwrap();
    art3.commit().unwrap();
    assert_eq!(
        art3.public_art()
            .node(&user_2_index)
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(&(secrets[1] + sk_1 + sk_2))
            .into_affine()
    );
}

#[test]
fn test_if_changes_are_applied_the_same_for_context_and_art() {
    init_tracing();

    let seed = 0;
    let mut rng = &mut StdRng::seed_from_u64(seed);
    let secrets = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let mut art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let mut art1 = PrivateArt::new(art0.public_art.clone(), secrets[1]).unwrap();

    for _ in 0..10 {
        let sk = Fr::rand(&mut rng);
        let (tk, branch_change) = art1.update_key(sk).unwrap();
        let change = PrivateBranchChange::new(sk, branch_change);
        change.apply(&mut art1).unwrap();

        change.apply(&mut art0).unwrap();
        art0.commit().unwrap();

        assert_eq!(
            &art1.preview().root().public_key(),
            &art0.root().data().public_key(),
            "fail to assert_eq on tree1:\n{}\n and merge context:\n{}",
            &art1.preview().root(),
            &art0.root(),
        );

        art1.commit().unwrap();
    }
}

/// The flow is the next:
/// - Epoch0: Create art, and init 5 users.
/// - Epoch1: update key (`user1`, `user2`, `user4`, `user5`), remove target member (`user3`)
/// - Epoch2:
#[test]
fn test_changes_ordering_for_merge() {
    init_tracing();

    let seed = 0;
    let mut rng = &mut StdRng::seed_from_u64(seed);
    let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let def_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

    let mut user0 = PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap();
    let mut user1 = PrivateArt::new(def_art.public_art.clone(), secrets[1]).unwrap();
    let mut user2 = PrivateArt::new(def_art.public_art.clone(), secrets[2]).unwrap();
    let mut user3 = PrivateArt::new(def_art.public_art.clone(), secrets[3]).unwrap();
    let mut user4 = PrivateArt::new(def_art.public_art.clone(), secrets[4]).unwrap();

    let mut user5 = PrivateArt::new(def_art.public_art.clone(), secrets[5]).unwrap();

    // Perform some changes
    let sk1 = Fr::rand(&mut rng);
    let sk2 = Fr::rand(&mut rng);
    let sk3 = Fr::rand(&mut rng);
    let sk4 = Fr::rand(&mut rng);
    let sk5 = Fr::rand(&mut rng);

    let target_user_public_key = CortadoAffine::generator().mul(secrets[6]).into_affine();
    let target_node_index = NodeIndex::from(
        user3
            .root()
            .path_to_leaf_with(target_user_public_key)
            .unwrap(),
    );

    let (_, change1) = user1.update_key(sk1).unwrap();
    let (_, change2) = user2.update_key(sk2).unwrap();
    let (_, change3) = user3.remove_member(&target_node_index, sk3).unwrap();
    let (_, change4) = user4.update_key(sk4).unwrap();
    let (_, change5) = user5.update_key(sk5).unwrap();

    let all_but_1_changes: Vec<BranchChange<CortadoAffine>> = vec![
        change2.clone(),
        change3.clone(),
        change4.clone(),
        change5.clone(),
    ];
    let all_changes = vec![
        change1.clone(),
        change2.clone(),
        change3.clone(),
        change4.clone(),
        change5.clone(),
    ];

    let root_key_pk = change1.public_keys.first().unwrap().clone()
        + change2.public_keys.first().unwrap().clone()
        + change3.public_keys.first().unwrap().clone()
        + change4.public_keys.first().unwrap().clone()
        + change5.public_keys.first().unwrap().clone();

    let root_key_pk = root_key_pk.into_affine();

    // Check correctness of the merge
    let mut user0_test_art = PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap();
    for change in &all_changes {
        change.apply(&mut user0_test_art).unwrap();
    }
    user0_test_art.commit().unwrap();

    let mut user1_test_art = user1.clone();
    sk1.apply(&mut user1_test_art).unwrap();
    for change in &all_but_1_changes {
        change.apply(&mut user1_test_art).unwrap();
    }
    user1_test_art.commit().unwrap();

    assert_eq!(user0_test_art, user1_test_art,);

    assert_eq!(user0_test_art.root_public_key(), root_key_pk);
    assert_eq!(user1_test_art.root_public_key(), root_key_pk);

    assert_eq!(
        user1_test_art, user0_test_art,
        "Observer and participant have the same view on the state of the art."
    );

    // check correctness for any permutation for user 0
    for permutation in all_but_1_changes
        .iter()
        .cloned()
        .permutations(all_but_1_changes.len())
    {
        let mut art_1_analog = user1.clone();
        sk1.apply(&mut art_1_analog).unwrap();
        for change in &permutation {
            change.apply(&mut art_1_analog).unwrap();
        }
        art_1_analog.commit().unwrap();

        assert_eq!(
            art_1_analog,
            user1_test_art,
            "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
            art_1_analog.root(),
            user1_test_art.root(),
        );
    }

    for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
        let mut art_0_analog = PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap();
        for change in permutation {
            change.apply(&mut art_0_analog).unwrap();
        }
        art_0_analog.commit().unwrap();

        assert_eq!(
            art_0_analog,
            user0_test_art,
            "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
            art_0_analog.root(),
            user0_test_art.root(),
        );
    }

    let all_users = [
        &mut user0, &mut user1, &mut user2, &mut user3, &mut user4, &mut user5,
    ];
    let all_private_changes = [
        PrivateBranchChange::new(sk1, change1),
        PrivateBranchChange::new(sk2, change2),
        PrivateBranchChange::new(sk3, change3),
        PrivateBranchChange::new(sk4, change4),
        PrivateBranchChange::new(sk5, change5),
    ];
    for user in all_users {
        for private_change in &all_private_changes {
            private_change.apply(user).unwrap();
        }
        user.commit().unwrap();
    }

    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);
    assert_eq!(user0, user4);
    assert_eq!(user0, user5);

    // Make more changes with user removal
    let sk0 = Fr::rand(rng);
    let sk1 = Fr::rand(rng);
    let sk2 = Fr::rand(rng);
    let sk3 = Fr::rand(rng);
    let sk4 = Fr::rand(rng);

    let (_, change0) = user0.remove_member(&target_node_index, sk0).unwrap();
    let (_, change1) = user1.update_key(sk1).unwrap();
    let (_, change2) = user2.leave_group(sk2).unwrap();
    let (_, change3) = user3.remove_member(&target_node_index, sk3).unwrap();
    let (_, change4) = user4.update_key(sk4).unwrap();

    let private2_change0 = PrivateBranchChange::new(sk0, change0);
    let private2_change1 = PrivateBranchChange::new(sk1, change1);
    let private2_change2 = PrivateBranchChange::new(sk2, change2);
    let private2_change3 = PrivateBranchChange::new(sk3, change3);
    let private2_change4 = PrivateBranchChange::new(sk4, change4);

    let all_changes = vec![
        private2_change0,
        private2_change1,
        private2_change2,
        private2_change3,
    ];

    let mut check_user = user0.clone();
    for change in &all_changes {
        change.apply(&mut check_user).unwrap();
    }
    check_user.commit().unwrap();

    for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
        let mut art_0_analog = user0.clone();
        for change in permutation {
            change.apply(&mut art_0_analog).unwrap();
        }
        art_0_analog.commit().unwrap();

        assert_eq!(
            art_0_analog,
            check_user,
            "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
            art_0_analog.root(),
            check_user.root(),
        );
    }
}

/// the flow is as next:
/// - Epoch1: remove some `target_user` with `user0`.
/// - Epoch2: update key (`user0`), confirm remove (`user1`).
/// - Epoch3: update key (`user0`, `user2`, `user3`).
#[test]
fn test_merge_flow_with_removal() {
    init_tracing();

    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let creator_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let public_art = creator_art.public_art().clone();

    // Create new users arts
    let mut user0 = creator_art;
    let mut user1 = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();
    let mut user2 = PrivateArt::new(public_art.clone(), secrets[2]).unwrap();
    let mut user3 = PrivateArt::new(public_art.clone(), secrets[8]).unwrap();
    let target_user = PrivateArt::new(public_art.clone(), secrets[5]).unwrap();

    // remove user
    let (_, epoch1_removal) = user0
        .remove_member(target_user.node_index(), Fr::rand(&mut rng))
        .unwrap();

    epoch1_removal.apply(&mut user0).unwrap();
    epoch1_removal.apply(&mut user1).unwrap();
    epoch1_removal.apply(&mut user2).unwrap();
    epoch1_removal.apply(&mut user3).unwrap();

    user0.commit().unwrap();
    user1.commit().unwrap();
    user2.commit().unwrap();
    user3.commit().unwrap();

    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);

    // Remove the same user for second time
    let (_, epoch2_removal) = user1
        .remove_member(target_user.node_index(), Fr::rand(&mut rng))
        .unwrap();
    let key_update_sk = Fr::rand(&mut rng);
    let (_, epoch2_key_update) = user0.update_key(key_update_sk).unwrap();
    let epoch2_key_update = PrivateBranchChange::new(key_update_sk, epoch2_key_update);

    epoch2_key_update.apply(&mut user0).unwrap();
    epoch2_removal.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    epoch2_removal.apply(&mut user1).unwrap();
    epoch2_key_update.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    epoch2_removal.apply(&mut user2).unwrap();
    epoch2_key_update.apply(&mut user2).unwrap();
    user2.commit().unwrap();

    epoch2_key_update.apply(&mut user3).unwrap();
    epoch2_removal.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    let root = *epoch2_removal.public_keys.first().unwrap()
        + *epoch2_key_update.change().public_keys.first().unwrap();
    let root = root.into_affine();

    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);

    // Create some concurrent changes
    let sk0 = Fr::rand(&mut rng);
    let (_, private_change0) = user0.update_key(sk0).unwrap();
    let change0 = PrivateBranchChange::new(sk0, private_change0.clone());

    let sk2 = Fr::rand(&mut rng);
    let (_, private_change2) = user2.update_key(sk2).unwrap();
    let change2 = PrivateBranchChange::new(sk2, private_change2.clone());

    let sk3 = Fr::rand(&mut rng);
    let (_, private_change3) = user3.update_key(sk3).unwrap();
    let change3 = PrivateBranchChange::new(sk3, private_change3.clone());

    let new_root = *change0.change().public_keys.first().unwrap()
        + *change2.change().public_keys.first().unwrap()
        + *change3.change().public_keys.first().unwrap();
    let new_root = new_root.into_affine();

    // Apply changes to ART trees. Use private_change to apply change of the user own key.
    change0.apply(&mut user0).unwrap();
    change2.apply(&mut user0).unwrap();
    change3.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    change0.apply(&mut user1).unwrap();
    change2.apply(&mut user1).unwrap();
    change3.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    change0.apply(&mut user2).unwrap();
    change2.apply(&mut user2).unwrap();
    change3.apply(&mut user2).unwrap();
    user2.commit().unwrap();

    change0.apply(&mut user3).unwrap();
    change2.apply(&mut user3).unwrap();
    change3.apply(&mut user3).unwrap();
    user3.commit().unwrap();

    assert_eq!(user0.root_public_key(), new_root);
    assert_eq!(user1.root_public_key(), new_root);
    assert_eq!(user2.root_public_key(), new_root);
    assert_eq!(user3.root_public_key(), new_root);

    // Now all the participants have the same view on the state of the art
    assert_eq!(user0, user1);
    assert_eq!(user0, user2);
    assert_eq!(user0, user3);
}

/// the flow is as next:
/// - Epoch1..: add new member with user `user0`.
/// - Epoch2..: update key (`user0`, `user1`).
#[test]
fn test_continuous_merge_update() {
    init_tracing();

    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let creator_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let public_art = creator_art.public_art().clone();

    // Create new users arts
    let mut user0 = creator_art;
    let mut user1 = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();
    let mut user2 = PrivateArt::new(public_art.clone(), secrets[2]).unwrap();
    let mut user3 = PrivateArt::new(public_art.clone(), secrets[3]).unwrap();

    verify_secrets_are_correct(&user0).unwrap();
    verify_secrets_are_correct(&user1).unwrap();
    verify_secrets_are_correct(&user2).unwrap();
    verify_secrets_are_correct(&user3).unwrap();

    for i in 0..7 {
        let new_user_secret = Fr::rand(&mut rng);
        let (_, change0) = user0.add_member(new_user_secret).unwrap();

        change0.apply(&mut user0).unwrap();
        change0.apply(&mut user1).unwrap();
        change0.apply(&mut user2).unwrap();
        change0.apply(&mut user3).unwrap();

        user0.commit().unwrap();
        user1.commit().unwrap();
        user2.commit().unwrap();
        user3.commit().unwrap();

        for user_i in [&user0, &user1, &user2, &user3].iter() {
            verify_secrets_are_correct(user_i).unwrap();
        }

        assert!(user0.node(user0.node_index()).unwrap().is_leaf());
        assert!(user1.node(user1.node_index()).unwrap().is_leaf());
        assert!(user2.node(user2.node_index()).unwrap().is_leaf());
        assert!(user3.node(user3.node_index()).unwrap().is_leaf());

        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);

        assert_eq!(user0.root_public_key(), user0.root().data().public_key());
        assert_eq!(user1.root_public_key(), user1.root().data().public_key());
        assert_eq!(user2.root_public_key(), user2.root().data().public_key());
        assert_eq!(user3.root_public_key(), user3.root().data().public_key());

        assert_eq!(
            user0.leaf_public_key(),
            user0
                .root()
                .node(user0.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user1.leaf_public_key(),
            user1
                .root()
                .node(user1.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user2.leaf_public_key(),
            user2
                .root()
                .node(user2.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user3.leaf_public_key(),
            user3
                .root()
                .node(user3.node_index())
                .unwrap()
                .data()
                .public_key()
        );
    }

    for user_i in [&user0, &user1, &user2, &user3].iter() {
        verify_secrets_are_correct(user_i).unwrap();
    }

    for i in 0..13 {
        let sk0 = Fr::rand(&mut rng);
        let sk1 = Fr::rand(&mut rng);
        let (_, change0) = user0.update_key(sk0).unwrap();
        let (_, change1) = user1.update_key(sk1).unwrap();
        let change0 = PrivateBranchChange::new(sk0, change0);
        let change1 = PrivateBranchChange::new(sk1, change1);

        let changes = [change0, change1];
        for (i, user_i) in [&mut user0, &mut user1, &mut user2, &mut user3]
            .iter_mut()
            .enumerate()
        {
            for (i, change) in changes.iter().enumerate() {
                change.apply(*user_i).unwrap();
                verify_secrets_are_correct(user_i).unwrap()
            }

            user_i.commit().unwrap();
            verify_secrets_are_correct(user_i).unwrap();

            assert_eq!(user_i.root_public_key(), user_i.root().data().public_key());
            assert_eq!(
                user_i.leaf_public_key(),
                user_i
                    .root()
                    .node(user_i.node_index())
                    .unwrap()
                    .data()
                    .public_key()
            );
        }

        assert_eq!(
            user0.root_secret_key(),
            user1.root_secret_key(),
            "User0:\n{:?}\nUser1\n{:?}",
            user0.secrets,
            user1.secrets,
        );
        assert_eq!(
            user0,
            user1,
            "User0:\n{}\nUser1\n{}",
            user0.root(),
            user1.root(),
        );
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);
    }

    for i in 0..27 {
        let sk0 = Fr::rand(&mut rng);
        let sk1 = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let sk3 = Fr::rand(&mut rng);
        let (_, change0) = user0.update_key(sk0).unwrap();
        let (_, change1) = user1.update_key(sk1).unwrap();
        let (_, change2) = user2.update_key(sk2).unwrap();
        let (_, change3) = user3.update_key(sk3).unwrap();
        let change0 = PrivateBranchChange::new(sk0, change0);
        let change1 = PrivateBranchChange::new(sk1, change1);
        let change2 = PrivateBranchChange::new(sk2, change2);
        let change3 = PrivateBranchChange::new(sk3, change3);

        let changes = [change0, change1, change2, change3];

        for user_i in [&mut user0, &mut user1, &mut user2, &mut user3].iter_mut() {
            for change in &changes {
                change.apply(*user_i).unwrap();
                verify_secrets_are_correct(&user_i).unwrap();
            }

            user_i.commit().unwrap();
        }

        verify_secrets_are_correct(&user0).unwrap();
        verify_secrets_are_correct(&user1).unwrap();
        verify_secrets_are_correct(&user2).unwrap();
        verify_secrets_are_correct(&user3).unwrap();

        assert_eq!(user0.public_art(), user1.public_art());
        assert_eq!(user0.public_art(), user2.public_art());
        assert_eq!(user0.public_art(), user3.public_art());

        assert_eq!(user0.root_public_key(), user0.root().data().public_key());
        assert_eq!(user1.root_public_key(), user1.root().data().public_key());
        assert_eq!(user2.root_public_key(), user2.root().data().public_key());
        assert_eq!(user3.root_public_key(), user3.root().data().public_key());

        assert_eq!(
            user0.leaf_public_key(),
            user0
                .root()
                .node(user0.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user1.leaf_public_key(),
            user1
                .root()
                .node(user1.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user2.leaf_public_key(),
            user2
                .root()
                .node(user2.node_index())
                .unwrap()
                .data()
                .public_key()
        );
        assert_eq!(
            user3.leaf_public_key(),
            user3
                .root()
                .node(user3.node_index())
                .unwrap()
                .data()
                .public_key()
        );

        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);
    }
}

pub(crate) fn verify_secrets_are_correct(
    private_art: &PrivateArt<CortadoAffine>,
) -> Result<(), ()> {
    let path = private_art.node_index().get_path().unwrap();

    let mut secrets = private_art
        .secrets
        .secrets()
        .iter()
        .rev()
        .cloned()
        .collect::<Vec<_>>();
    let mut preview_secrets = Vec::new();
    let mut i = 0;
    while let Some(sk) = private_art.secrets.preview().secret(i) {
        preview_secrets.push(sk);
        i += 1;
    }
    preview_secrets.reverse();

    // trace!("secrets verification: {:#?}\n\ton path: {:?}", secrets, path);
    let root_secret = secrets.pop().unwrap();
    let root_secret_preview = preview_secrets.pop().unwrap();

    let mut parent = private_art.root();
    let mut parent_preview = private_art.preview().root();

    // trace!("parent:\n{}", parent);

    if parent
        .data()
        .public_key()
        .ne(&CortadoAffine::generator().mul(root_secret).into_affine())
    {
        error!(
            "error in root computations:\n\tsk: {},\n\treal pk_x: {:?},\n\tcomputed pk: {:?}\n for tree:\n{}",
            root_secret,
            parent.data().public_key().x(),
            CortadoAffine::generator()
                .mul(root_secret)
                .into_affine()
                .x(),
            private_art.root()
        );
        return Err(());
    }

    if parent_preview
        .public_key()
        .ne(&CortadoAffine::generator().mul(root_secret_preview).into_affine())
    {
        error!(
            "error in root computations:\n\tsk: {},\n\treal pk_x: {:?},\n\tcomputed pk: {:?}\n for tree:\n{}",
            root_secret,
            parent.data().public_key().x(),
            CortadoAffine::generator()
                .mul(root_secret)
                .into_affine()
                .x(),
            private_art.root()
        );
        return Err(());
    }

    for (sk, dir) in secrets.iter().rev().zip(path.iter()) {
        parent = parent.child(*dir).unwrap();

        if parent
            .data()
            .public_key()
            .ne(&CortadoAffine::generator().mul(sk).into_affine())
        {
            error!(
                "error in computations:\n\tsk: {},\n\treal pk_x: {:?},\n\tcomputed pk: {:?}\n for tree:\n{}",
                sk,
                parent.data().public_key().x(),
                CortadoAffine::generator().mul(sk).into_affine().x(),
                private_art.root()
            );
            return Err(());
        }
    }

    Ok(())
}

#[test]
fn test_key_update_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let mut art = private_art;
    let test_art = PrivateArt::new(public_art, secrets[1]).unwrap();

    let new_secret_key = Fr::rand(&mut rng);
    let associated_data = b"Some data for proof";

    let (tk, change, prover_branch) = art.update_key(new_secret_key).unwrap();
    let change = PrivateBranchChange::new(new_secret_key, change);
    let member_el = member_leaf_eligibility_artefact(&art);
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        change.change().public_keys[0]
    );
    let tk = change.apply(&mut art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        change.change().public_keys[0]
    );
    art.commit().unwrap();

    let proof = prover_engine
        .new_context(member_el)
        .for_branch(&prover_branch)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();
    let key_update_change = change.change();

    assert_eq!(
        art.root().data().public_key(),
        CortadoAffine::generator()
            .mul(art.root_secret_key())
            .into_affine()
    );

    let eligibility_requirement = EligibilityRequirement::Member(
        test_art
            .node(&key_update_change.node_index)
            .unwrap()
            .data()
            .public_key(),
    );
    let deserialized_proof = ArtProof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    let verification_branch = test_art
        .public_art()
        .verification_branch(&key_update_change)
        .unwrap();

    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&verification_branch)
        .verify(&deserialized_proof);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );
}

#[test]
fn test_double_key_update_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(rand::random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let mut user0 = private_art;

    let mut user1 = PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

    let mut user2 = PrivateArt::new(public_art.clone(), secrets[2]).unwrap();

    let associated_data0_0 = b"Some data for proof";
    let associated_data0_1 = b"another data for proof";

    let (_, key_update_change0_0, prover_branch0_0) = user0.update_key(Fr::rand(&mut rng)).unwrap();
    let (_, key_update_change0_1, prover_branch0_1) = user1.update_key(Fr::rand(&mut rng)).unwrap();

    let proof0_0 = prover_engine
        .new_context(member_leaf_eligibility_artefact(&user0))
        .for_branch(&prover_branch0_0)
        .with_associated_data(associated_data0_0)
        .prove(&mut thread_rng())
        .unwrap();

    let proof0_1 = prover_engine
        .new_context(member_leaf_eligibility_artefact(&user1))
        .for_branch(&prover_branch0_1)
        .with_associated_data(associated_data0_1)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement0_0 = EligibilityRequirement::Member(
        user2
            .node(&key_update_change0_0.node_index)
            .unwrap()
            .data()
            .public_key(),
    );

    verifier_engine
        .new_context(eligibility_requirement0_0)
        .with_associated_data(associated_data0_0)
        .for_branch(&user2.verification_branch(&key_update_change0_0).unwrap())
        .verify(&proof0_0)
        .unwrap();

    user2.apply(&key_update_change0_0).unwrap();

    let eligibility_requirement0_1 = EligibilityRequirement::Member(
        user2
            .node(&key_update_change0_1.node_index)
            .unwrap()
            .data()
            .public_key(),
    );

    verifier_engine
        .new_context(eligibility_requirement0_1)
        .with_associated_data(associated_data0_1)
        .for_branch(&user2.verification_branch(&key_update_change0_1).unwrap())
        .verify(&proof0_1)
        .unwrap();

    user2.apply(&key_update_change0_1).unwrap();

    user2.commit().unwrap()
}

#[test]
fn test_make_blank_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(rand::random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let main_rng = Box::new(StdRng::seed_from_u64(rand::random()));
    let mut art = private_art;
    let test_art = PrivateArt::new(public_art, secrets[1]).unwrap();

    let target_public_key = CortadoAffine::generator().mul(secrets[1]).into_affine();
    let target_node_path = art.root().path_to_leaf_with(target_public_key).unwrap();
    let target_node_index = NodeIndex::from(target_node_path);
    let new_secret_key = Fr::rand(&mut rng);

    let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];

    let (_, make_blank_change_output, prover_branch) = art
        .remove_member(&target_node_index, new_secret_key)
        .unwrap();
    let tk = make_blank_change_output.apply(&mut art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        make_blank_change_output.public_keys[0]
    );

    let proof = prover_engine
        .new_context(removal_eligibility(&art, &target_node_index))
        .for_branch(&prover_branch)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let make_blank_change = BranchChange::from(make_blank_change_output);

    let tk = art.root_secret_key();

    let eligibility_requirement =
        EligibilityRequirement::Previleged((art.leaf_public_key(), vec![]));

    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&test_art.verification_branch(&make_blank_change).unwrap())
        .verify(&proof);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );
}

#[test]
fn test_leave_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(rand::random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let mut art = private_art;
    let mut test_art = PrivateArt::new(public_art, secrets[1]).unwrap();

    let new_secret_key = Fr::rand(&mut rng);
    let associated_data = b"Some data for proof";

    let (_, leave_group_change, prover_branch) = art.leave_group(new_secret_key).unwrap();

    let proof = prover_engine
        .new_context(member_leaf_eligibility_artefact(&art))
        .for_branch(&prover_branch)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    assert_eq!(
        art.root().data().public_key(),
        CortadoAffine::generator()
            .mul(art.root_secret_key())
            .into_affine()
    );

    let eligibility_requirement = EligibilityRequirement::Member(
        test_art
            .root()
            .node(&leave_group_change.node_index)
            .unwrap()
            .data()
            .public_key(),
    );
    let deserialized_proof = ArtProof::deserialize_compressed(proof_bytes.as_slice()).unwrap();
    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&test_art.verification_branch(&leave_group_change).unwrap())
        .verify(&deserialized_proof);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );

    // Try to remove leaf with LeafStatus::PendingBalance
    leave_group_change.apply(&mut test_art).unwrap();
    test_art.commit().unwrap();
    // info!("test_art:\n{}", test_art.base_art.get_root());
    let (_, remove_change, prover_branch) = test_art
        .remove_member(art.node_index(), Fr::rand(&mut rng))
        .unwrap();

    let proof = prover_engine
        .new_context(removal_eligibility(&test_art, art.node_index()))
        .for_branch(&prover_branch)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement = EligibilityRequirement::Member(test_art.root_public_key());

    verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&test_art.verification_branch(&remove_change).unwrap())
        .verify(&proof)
        .unwrap();
}

#[test]
fn test_append_node_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(rand::random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let mut art = private_art;
    let test_art = PrivateArt::new(public_art, secrets[1]).unwrap();
    let public_key = art.leaf_public_key();

    let new_secret_key = Fr::rand(&mut rng);
    let (_, append_node_changes, prover_branch) = art.add_member(new_secret_key).unwrap();

    let tk = append_node_changes.apply(&mut art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        append_node_changes.public_keys[0]
    );
    art.commit().unwrap();

    let associated_data = &[2, 3, 4, 5, 6, 7, 8, 9, 10];
    let proof = prover_engine
        .new_context(owner_leaf_eligibility_artefact(&art))
        .for_branch(&prover_branch)
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement = EligibilityRequirement::Previleged((public_key, vec![]));

    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data)
        .for_branch(&test_art.verification_branch(&append_node_changes).unwrap())
        .verify(&proof);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );
}

#[test]
fn test_append_node_changes_creation() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(rand::random());
    let secrets = (0..TEST_GROUP_SIZE)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let mut user1 = PrivateArt::new(user0.public_art().clone(), secrets[1]).unwrap();
    let mut user2 = PrivateArt::new(user0.public_art().clone(), secrets[2]).unwrap();

    let (_, removal_change0, _) = user0
        .remove_member(user2.node_index(), Fr::rand(&mut rng))
        .unwrap();

    user0.apply(&removal_change0).unwrap();
    user1.apply(&removal_change0).unwrap();

    let (_, append_node_change1, _) = user0.add_member(Fr::rand(&mut rng)).unwrap();

    user0.commit().unwrap();
    user1.commit().unwrap();

    user0.apply(&append_node_change1).unwrap();
    user1.apply(&append_node_change1).unwrap();

    for _ in 0..10 {
        let (_, append_node_change2, _) = user0.add_member(Fr::rand(&mut rng)).unwrap();

        user0.commit().unwrap();
        user0.apply(&append_node_change2).unwrap();

        user1.commit().unwrap();
        user1.apply(&append_node_change2).unwrap();
    }
}

#[test]
fn test_append_node_after_make_blank_proof() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = StdRng::seed_from_u64(0);
    // Use power of two, so all branches have equal weight. Then any blank node will be the
    // one to be replaced at node addition.
    let art_size = 2usize.pow(3);
    let secrets = (0..art_size)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let public_art = private_art.public_art().clone();

    let mut art = private_art;
    let mut test_art = PrivateArt::new(public_art, secrets[1]).unwrap();

    // let secret_key = art.get_base_art().get_leaf_secret_key();
    let public_key = art.leaf_public_key();
    let new_secret_key = Fr::rand(&mut rng);

    let associated_data1 = b"asdlkfhalkehafksjdhkflasfsadfsdf";
    let associated_data2 = b"sdfksdhfjasdfaskhekjfaskldfsdfdf";

    // Make blank the node with index 1
    let target_public_key = CortadoAffine::generator().mul(secrets[4]).into_affine();
    let target_node_path = art.root().path_to_leaf_with(target_public_key).unwrap();
    let target_node_index = NodeIndex::from(target_node_path);

    let (_, make_blank_changes, prover_branch) = art
        .remove_member(&target_node_index, new_secret_key)
        .unwrap();
    let tk = make_blank_changes.apply(&mut art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        make_blank_changes.public_keys[0]
    );
    art.commit().unwrap();

    let proof1 = prover_engine
        .new_context(owner_leaf_eligibility_artefact(&art))
        .for_branch(&prover_branch)
        .with_associated_data(associated_data1)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement =
        EligibilityRequirement::Previleged((art.leaf_public_key(), vec![]));

    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .with_associated_data(associated_data1)
        .for_branch(&test_art.verification_branch(&make_blank_changes).unwrap())
        .verify(&proof1);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );

    let tk = make_blank_changes.apply(&mut test_art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        make_blank_changes.public_keys[0].clone()
    );
    test_art.commit().unwrap();

    assert_eq!(
        public_key,
        CortadoAffine::generator()
            .mul(art.leaf_secret_key())
            .into_affine(),
    );
    assert_eq!(
        art.root()
            .node(art.node_index())
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(art.leaf_secret_key())
            .into_affine()
    );

    let (_, append_node_changes, prover_branch2) = art.add_member(new_secret_key).unwrap();
    let tk = append_node_changes.apply(&mut art).unwrap();
    assert_eq!(
        CortadoAffine::generator().mul(tk).into_affine(),
        append_node_changes.public_keys[0]
    );
    art.commit().unwrap();

    assert_eq!(
        public_key,
        art.root()
            .node(art.node_index())
            .unwrap()
            .data()
            .public_key(),
    );
    assert_eq!(
        art.root()
            .node(art.node_index())
            .unwrap()
            .data()
            .public_key(),
        CortadoAffine::generator()
            .mul(art.leaf_secret_key())
            .into_affine()
    );

    let proof2 = prover_engine
        .new_context(owner_leaf_eligibility_artefact(&art))
        .for_branch(&prover_branch2)
        .with_associated_data(associated_data2)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement =
        EligibilityRequirement::Previleged((art.leaf_public_key(), vec![]));

    let verification_result = verifier_engine
        .new_context(eligibility_requirement)
        .for_branch(&test_art.verification_branch(&append_node_changes).unwrap())
        .with_associated_data(associated_data2)
        .verify(&proof2);

    assert!(
        matches!(verification_result, Ok(())),
        "Must successfully verify, while get {:?} result",
        verification_result
    );
}

/// the flow is as next:
/// - Epoch1..: add new member with user `user0`.
/// - Epoch2..: update key (`user0`, `user1`).
#[test]
fn test_merge_proof_verify() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    let mut rng = &mut StdRng::seed_from_u64(0);
    let secrets: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let creator_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
    let public_art = creator_art.public_art().clone();

    // Create new users arts
    let mut user0 = creator_art;
    let test_users = 4usize;

    let mut users = (0..test_users)
        .map(|i| PrivateArt::new(public_art.clone(), secrets[i]).unwrap())
        .collect::<Vec<_>>();

    let sk = std::iter::repeat_with(|| Fr::rand(&mut rng))
        .take(4)
        .collect::<Vec<_>>();

    let mut private_changes = Vec::with_capacity(test_users);
    let mut proofs = Vec::with_capacity(test_users);
    let mut associated_data = Vec::with_capacity(test_users);
    for (i, user) in users.iter_mut().enumerate() {
        let (_, change, prover_branch) = user.update_key(sk[i]).unwrap();

        private_changes.push(PrivateBranchChange::new(sk[i], change));

        let prover_eligibility =
            EligibilityArtefact::Member((user.leaf_secret_key(), user.leaf_public_key()));

        let ad = std::iter::repeat_with(|| random::<u8>())
            .take(20)
            .collect::<Vec<_>>();

        let proof = prover_engine
            .new_context(prover_eligibility)
            .for_branch(&prover_branch)
            .with_associated_data(&ad)
            .prove(&mut thread_rng())
            .unwrap();

        proofs.push(proof);
        associated_data.push(ad);
    }

    for (i, user) in users.iter_mut().enumerate() {
        for (j, change) in private_changes.iter().enumerate() {
            let prover_leaf = user
                .node(&change.change().node_index)
                .unwrap()
                .data()
                .public_key();
            let eligibility_requirement = EligibilityRequirement::Member(prover_leaf);

            verifier_engine
                .new_context(eligibility_requirement)
                .with_associated_data(&associated_data[j])
                .for_branch(&user.verification_branch(change.change()).unwrap())
                .verify(&proofs[j])
                .unwrap();

            user.apply(change).unwrap();
        }
    }

    users[0].commit().unwrap();
    let sk = Fr::rand(&mut rng);
    let (_, change, prover_branch) = users[0].update_key(sk).unwrap();
    users[0].apply(&sk).unwrap();
    users[0].commit().unwrap();

    let prover_eligibility =
        EligibilityArtefact::Member((users[0].leaf_secret_key(), users[0].leaf_public_key()));

    let ad = std::iter::repeat_with(|| random::<u8>())
        .take(20)
        .collect::<Vec<_>>();

    let proof = prover_engine
        .new_context(prover_eligibility)
        .for_branch(&prover_branch)
        .with_associated_data(&ad)
        .prove(&mut thread_rng())
        .unwrap();

    let eligibility_requirement = EligibilityRequirement::Member(users[0].leaf_public_key());
    for (i, user) in users.iter_mut().enumerate().skip(1) {
        let result = verifier_engine
            .new_context(eligibility_requirement.clone())
            .with_associated_data(&ad)
            .for_branch(&user.verification_branch(&change).unwrap())
            .verify(&proof);

        assert!(matches!(result, Err(_)));

        let result = verifier_engine
            .new_context(eligibility_requirement.clone())
            .with_associated_data(&ad)
            .for_branch(&user.preview().verification_branch(&change).unwrap())
            .verify(&proof);

        assert!(matches!(result, Ok(_)));

        user.commit().unwrap();

        let result = verifier_engine
            .new_context(eligibility_requirement.clone())
            .with_associated_data(&ad)
            .for_branch(&user.preview().verification_branch(&change).unwrap())
            .verify(&proof);

        assert!(matches!(result, Ok(_)));

        user.commit().unwrap();
        user.apply(&change).unwrap();
        user.commit().unwrap();
    }

    for user in users.iter() {
        assert_eq!(&users[0], user);
    }
}

pub(crate) fn member_leaf_eligibility_artefact(
    art: &PrivateArt<CortadoAffine>,
) -> EligibilityArtefact {
    EligibilityArtefact::Member((art.leaf_secret_key(), art.leaf_public_key()))
}

pub(crate) fn owner_leaf_eligibility_artefact(
    art: &PrivateArt<CortadoAffine>,
) -> EligibilityArtefact {
    EligibilityArtefact::Owner((art.leaf_secret_key(), art.leaf_public_key()))
}

pub(crate) fn root_eligibility_artefact(art: &PrivateArt<CortadoAffine>) -> EligibilityArtefact {
    EligibilityArtefact::Member((art.root_secret_key(), art.root_public_key()))
}

pub(crate) fn removal_eligibility(
    art: &PrivateArt<CortadoAffine>,
    index: &NodeIndex,
) -> EligibilityArtefact {
    let leaf_status = art.root().node(index).unwrap().data().status();
    if leaf_status.is_none() {
        warn!("Trying to remove internal node, as it have leaf_status: None");
    }

    if matches!(leaf_status, Some(LeafStatus::Active)) {
        owner_leaf_eligibility_artefact(art)
    } else {
        root_eligibility_artefact(art)
    }
}
