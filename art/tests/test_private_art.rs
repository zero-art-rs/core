mod utils;

#[cfg(test)]
mod tests {
    use super::utils::init_tracing_for_test;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::EdwardsAffine as Ed25519Affine;
    use ark_ff::Field;
    use ark_std::UniformRand;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use bulletproofs::PedersenGens;
    use bulletproofs::r1cs::R1CSError;
    use cortado::{CortadoAffine, Fr};
    use itertools::Itertools;
    use rand::rng;
    use rand::seq::IteratorRandom;
    use std::cmp::{max, min};
    use std::ops::{Add, Mul};
    use tracing::{debug, error, info, warn};
    use zkp::toolbox::{cross_dleq::PedersenBasis, dalek_ark::ristretto255_to_ark};
    use zrt_art::aggregations::{
        AggregationData, AggregationNodeIterWithPath, ChangeAggregation, PlainChangeAggregation,
        ProverAggregationData, ProverChangeAggregation, VerifierAggregationData,
    };
    use zrt_art::art::{
        ARTRootKey, LeafIterWithPath, LeafStatus, PrivateART, ProverArtefacts, PublicART,
        VerifierArtefacts,
    };
    use zrt_art::errors::ARTError;
    use zrt_art::helper_tools::iota_function;
    use zrt_art::node_index::NodeIndex;
    use zrt_art::tree_node::TreeNode;
    use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};
    use zrt_zk::aggregated_art::{art_aggregated_prove, art_aggregated_verify};
    use zrt_zk::art::{art_prove, art_verify};

    pub const TEST_GROUP_SIZE: usize = 100;

    /// User creates art with one node and appends new user. New user updates his sk.
    #[test]
    fn test_flow_append_join_update() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);

        let (mut user0, def_tk) =
            PrivateART::new_art_from_secrets(&vec![secret_key_0], &CortadoAffine::generator())
                .unwrap();

        // Add member with user0
        let secret_key_1 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        let (ap_tk, changes, _) = user0.append_or_replace_node(&secret_key_1).unwrap();

        assert_eq!(
            user0.get_secret_key(),
            user0.get_path_secrets()[0],
            "user secret_key is present in path_secrets"
        );
        assert_eq!(
            user0
                .get_public_art()
                .get_node(&changes.node_index)
                .unwrap()
                .get_public_key(),
            user0.public_key_of(&secret_key_1),
            "New node is in the art, and it is on the correct path.",
        );
        assert_eq!(
            user0
                .get_public_art()
                .get_node(&user0.get_node_index())
                .unwrap()
                .get_public_key(),
            user0.public_key_of(&secret_key_0),
            "User node is isn't changed, after append member request.",
        );
        assert_eq!(
            ap_tk,
            user0.get_root_key().unwrap(),
            "Sanity check: returned tk is the same as the stored one.",
        );
        assert_ne!(
            ap_tk, def_tk,
            "Sanity check: new tk is different from the old one.",
        );
        assert_ne!(
            user0
                .get_public_art()
                .get_node(&changes.node_index)
                .unwrap()
                .get_public_key(),
            user0
                .get_public_art()
                .get_node(&user0.get_node_index())
                .unwrap()
                .get_public_key(),
            "Sanity check: Both users nodes have different public key.",
        );

        // Serialise and deserialize art for the new user.
        let public_art_bytes = user0.serialize().unwrap();
        assert_ne!(secret_key_0, secret_key_1);
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        assert_ne!(
            user0.get_path_secrets(),
            user1.get_path_secrets(),
            "Sanity check: Both users have different path secrets"
        );
        assert!(user0.eq(&user1), "New user received the same art");
        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );

        let tk0 = user0.get_root_key().unwrap();
        let tk1 = user1.get_root_key().unwrap();

        let secret_key_3 = Fr::rand(&mut rng);

        // New user updates his key
        let (tk, change_key_update, _) = user1.update_key(&secret_key_3).unwrap();
        assert_ne!(
            tk1,
            user1.get_root_key().unwrap(),
            "Sanity check: old tk is different from the stored one."
        );
        assert_eq!(
            tk,
            user1.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet"
        );

        user0.update(&change_key_update).unwrap();

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_ne!(
            tk0, tk,
            "Sanity check: old tk is different from the new one."
        );
        assert_eq!(
            tk,
            user0.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );
    }

    /// Creator, after computing the art with several users, removes the target_user. The
    /// remaining users updates their art, and one of them, also removes target_user (instead
    /// or changing, he merges two updates). Removed user fails to update his art.
    #[test]
    fn test_removal_of_the_same_user() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2, secret_key_3],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        let mut user2: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_2).unwrap();

        let mut user3: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_3).unwrap();

        assert_ne!(
            user0.get_path_secrets(),
            user1.get_path_secrets(),
            "Sanity check: Both users have different path secrets"
        );
        assert_ne!(
            user0.get_path_secrets(),
            user2.get_path_secrets(),
            "Sanity check: Both users have different path secrets"
        );
        assert_ne!(
            user2.get_path_secrets(),
            user1.get_path_secrets(),
            "Sanity check: Both users have different path secrets"
        );
        assert_ne!(
            user3.get_path_secrets(),
            user1.get_path_secrets(),
            "Sanity check: Both users have different path secrets"
        );
        assert!(user0.eq(&user1), "New user received the same art");
        assert!(user0.eq(&user2), "New user received the same art");
        assert!(user0.eq(&user3), "New user received the same art");

        let tk0 = user0.get_root_key().unwrap();
        let tk1 = user1.get_root_key().unwrap();
        let tk2 = user2.get_root_key().unwrap();
        let tk3 = user2.get_root_key().unwrap();

        let blanking_secret_key_1 = Fr::rand(&mut rng);
        let blanking_secret_key_2 = Fr::rand(&mut rng);

        // User0 removes second user node from the art.
        let (tk_r1, remove_member_change1, _) = user0
            .make_blank(
                &user2.get_node_index().get_path().unwrap(),
                &blanking_secret_key_1,
            )
            .unwrap();
        assert_ne!(
            tk1,
            user0.get_root_key().unwrap(),
            "Sanity check: old tk is different from the stored one."
        );
        assert_eq!(
            tk_r1,
            user0.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
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
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            user0.public_key_of(&blanking_secret_key_1),
            "The node was removed correctly."
        );

        // Sync other users art
        user1.update(&remove_member_change1).unwrap();
        user3.update(&remove_member_change1).unwrap();

        assert!(
            matches!(
                user2.update(&remove_member_change1).err(),
                Some(ARTError::InapplicableBlanking)
            ),
            "Cant perform art update using blank leaf."
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
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            user1.public_key_of(&blanking_secret_key_1),
            "The node was removed correctly."
        );

        // User1 removes second user node from the art.
        let (tk_r2, remove_member_change2, _) = user1
            .make_blank(
                &user2.get_node_index().get_path().unwrap(),
                &blanking_secret_key_2,
            )
            .unwrap();
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&remove_member_change2.node_index)
                .unwrap()
                .get_public_key(),
            user1.public_key_of(&(blanking_secret_key_1 + blanking_secret_key_2)),
            "The node was removed correctly."
        );
        assert_eq!(
            user1.get_root().get_public_key(),
            user1.public_key_of(&tk_r2.key),
            "The node was removed correctly."
        );
        assert_ne!(
            tk_r1, tk_r2,
            "Sanity check: old tk is different from the new one."
        );
        assert_eq!(
            tk_r2,
            user1.get_root_key().unwrap(),
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
        user0.update(&remove_member_change2).unwrap();
        user3.update(&remove_member_change2).unwrap();

        assert_eq!(
            user0.get_root_key().ok(),
            user1.get_root_key().ok(),
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
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            user1.public_key_of(&(blanking_secret_key_1 + blanking_secret_key_2)),
            "The node was removed correctly."
        );
    }

    /// Main user creates art with four users, then first, second, and third users updates their
    /// arts. The forth user, applies changes, but swaps first two.
    #[test]
    fn test_wrong_update_ordering() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        assert_ne!(secret_key_1, secret_key_2);
        assert_ne!(secret_key_2, secret_key_3);

        let (mut user0, def_tk) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2, secret_key_3],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        let mut user2: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_2).unwrap();

        let mut user3: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_3).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk_r0, key_update_change0, _) = user0.update_key(&new_sk0).unwrap();
        assert_eq!(
            tk_r0,
            user0.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User1 updates his art.
        user1.update(&key_update_change0).unwrap();
        let new_sk1 = Fr::rand(&mut rng);
        let (tk_r1, key_update_change1, _) = user1.update_key(&new_sk1).unwrap();
        assert_eq!(
            tk_r1,
            user1.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User2 updates his art.
        user2.update(&key_update_change0).unwrap();
        user2.update(&key_update_change1).unwrap();
        let new_sk2 = Fr::rand(&mut rng);
        let (tk_r2, key_update_change2, _) = user2.update_key(&new_sk2).unwrap();
        assert_eq!(
            tk_r2,
            user2.get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Update art for other users.
        user3.update(&key_update_change1).unwrap();
        user3.update(&key_update_change0).unwrap();
        user3.update(&key_update_change2).unwrap();

        assert_ne!(
            user3.get_root(),
            user2.get_root(),
            "Wrong order of updates will bring to different public arts."
        );
    }

    /// The same key update, shouldn't affect the art, as it will be overwritten by itself.
    #[test]
    fn test_apply_key_update_changes_twice() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);

        let (mut user0, def_tk) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2, secret_key_3],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk_r0, key_update_change0, _) = user0.update_key(&new_sk0).unwrap();

        // Update art for other users.
        user1.update(&key_update_change0).unwrap();
        user1.update(&key_update_change0).unwrap();

        assert_eq!(
            user0, user1,
            "Applying of the same key update twice, will give no affect."
        );
    }

    #[test]
    fn test_from_applications() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let (user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2, secret_key_3],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_0).unwrap();

        let user1_2 = PrivateART::from_public_art_and_path_secrets(
            PublicART::from(user1.clone()),
            user1.get_path_secrets().clone(),
        )
        .unwrap();

        assert_eq!(user1, user1_2);

        assert_eq!(user1.get_path_secrets(), user1_2.get_path_secrets(),);
    }

    #[test]
    fn test_get_node() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let leaf_secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &leaf_secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();

        let random_public_key = CortadoAffine::rand(&mut rng);
        assert!(
            user0
                .get_public_art()
                .get_node_with(&random_public_key)
                .is_err()
        );
        assert!(
            user0
                .get_mut_public_art()
                .get_mut_node_with(&random_public_key)
                .is_err()
        );
        assert!(
            user0
                .get_public_art()
                .get_leaf_with(&random_public_key)
                .is_err()
        );
        assert!(
            user0
                .get_mut_public_art()
                .get_mut_leaf_with(&random_public_key)
                .is_err()
        );

        for sk in &leaf_secrets {
            let pk = user0.public_key_of(sk);
            assert_eq!(
                user0
                    .get_public_art()
                    .get_leaf_with(&pk)
                    .unwrap()
                    .get_public_key(),
                pk,
            )
        }

        for sk in &leaf_secrets {
            let pk = user0.public_key_of(sk);
            assert_eq!(
                user0
                    .get_mut_public_art()
                    .get_mut_leaf_with(&pk)
                    .unwrap()
                    .get_public_key(),
                pk,
            )
        }

        for sk in &leaf_secrets {
            let pk = user0.public_key_of(sk);
            let leaf = user0.get_public_art().get_node_with(&pk).unwrap();
            assert_eq!(leaf.get_public_key(), pk,);

            assert!(leaf.is_leaf());
        }

        for sk in &leaf_secrets {
            let pk = user0.public_key_of(sk);
            let leaf = user0.get_mut_public_art().get_mut_node_with(&pk).unwrap();
            assert_eq!(leaf.get_public_key(), pk,);

            assert!(leaf.is_leaf());
        }

        for sk in &leaf_secrets {
            let pk = user0.public_key_of(sk);
            let leaf_path = user0.get_public_art().get_path_to_leaf(&pk).unwrap();
            let leaf = user0
                .get_public_art()
                .get_node(&NodeIndex::Direction(leaf_path))
                .unwrap();
            assert_eq!(leaf.get_public_key(), pk,);

            assert!(leaf.is_leaf());
        }
    }

    /// Test if apply of changes to itself will fail
    #[test]
    fn test_apply_key_update_to_itself() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2, secret_key_3],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_0).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let (tk_r0, key_update_change0, _) = user0.update_key(&new_sk0).unwrap();

        // User1 fails to update his art.
        assert!(matches!(
            user1.update(&key_update_change0),
            Err(ARTError::InapplicableKeyUpdate)
        ));
    }

    #[test]
    fn test_art_key_update() {
        init_tracing_for_test();

        let mut rng = StdRng::seed_from_u64(0);
        let main_user_id = 0;
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut users_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            users_arts.push(
                PrivateART::from_public_art_and_secret(public_art.clone(), secrets[i]).unwrap(),
            );
        }

        for i in 0..TEST_GROUP_SIZE {
            // Assert creator and users computed the same tree key.
            assert_eq!(users_arts[i].get_root_key().unwrap().key, root_key.key);
        }

        let mut main_user_art = users_arts[main_user_id].clone();

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = Fr::rand(&mut rng);
        let (new_key, changes, _) = main_user_art.update_key(&main_new_key).unwrap();
        assert_ne!(new_key.key, main_old_key);

        let mut pub_keys = Vec::new();
        let mut parent = main_user_art.get_root();
        for direction in &main_user_art.get_node_index().get_path().unwrap() {
            pub_keys.push(parent.get_child(*direction).unwrap().get_public_key());
            parent = parent.get_child(*direction).unwrap();
        }
        pub_keys.reverse();

        for (secret_key, corr_pk) in main_user_art.get_path_secrets().iter().zip(pub_keys.iter()) {
            assert_eq!(
                CortadoAffine::generator().mul(secret_key).into_affine(),
                *corr_pk,
                "Multiplication done correctly."
            );
        }

        let test_user_id = 12;
        users_arts[test_user_id].update(&changes).unwrap();
        assert_eq!(
            users_arts[test_user_id].get_root_key().unwrap().key,
            new_key.key
        );
        assert_eq!(new_key, users_arts[test_user_id].get_root_key().unwrap());

        let (recomputed_old_key, changes, _) = main_user_art.update_key(&main_old_key).unwrap();

        assert_eq!(root_key.key, recomputed_old_key.key);

        for i in 0..TEST_GROUP_SIZE {
            if i != main_user_id {
                users_arts[i].update(&changes).unwrap();
                assert_eq!(
                    users_arts[i].get_root_key().unwrap().key,
                    recomputed_old_key.key
                );
                assert_eq!(recomputed_old_key, users_arts[i].get_root_key().unwrap());
            }
        }
    }

    #[test]
    fn test_art_weights_correctness() {
        let secrets = create_random_secrets(TEST_GROUP_SIZE);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 1..TEST_GROUP_SIZE {
            let _ = tree.append_or_replace_node(&Fr::rand(&mut rng)).unwrap();

            assert_eq!(
                tree.get_secret_key(),
                tree.get_path_secrets()[0],
                "user secret_key is present in path_secrets"
            );
        }

        for node in tree.get_root() {
            if node.is_leaf() {
                if !node.is_active() {
                    assert_eq!(node.get_weight(), 0);
                } else {
                    assert_eq!(node.get_weight(), 1);
                }
            } else {
                assert_eq!(
                    node.get_weight(),
                    node.get_left().unwrap().get_weight() + node.get_right().unwrap().get_weight()
                );
            }
        }
    }

    #[test]
    fn test_changes_ordering_for_merge() {
        init_tracing_for_test();

        let seed = rand::random();
        // debug!("test_changes_ordering: seed: {}", seed);
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, rng);

        let (art0, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        // Serialise and deserialize art for the new user.
        let public_art_bytes = art0.serialize().unwrap();

        let art1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[1]).unwrap();

        // Create new users for testing
        let mut user0: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[0]).unwrap();

        let mut user2: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[2]).unwrap();

        let mut user3: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[8]).unwrap();

        let mut user4: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[10]).unwrap();

        let mut user5: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[67]).unwrap();

        let sk0 = Fr::rand(&mut rng);
        let (_, change0, _) = user0.update_key(&sk0).unwrap();

        // let sk1 = Fr::rand(&mut rng);
        // let (_, change1, _) = user1.update_key(&sk1).unwrap();

        let sk2 = Fr::rand(&mut rng);
        let (_, change2, _) = user2.update_key(&sk2).unwrap();

        let sk3 = Fr::rand(&mut rng);
        let (_, change3, _) = user3
            .make_blank(
                &user3
                    .get_public_art()
                    .get_path_to_leaf(&user3.public_key_of(&secrets[25]))
                    .unwrap(),
                &sk3,
            )
            .unwrap();

        let sk4 = Fr::rand(&mut rng);
        let (_, change4, _) = user4.update_key(&sk4).unwrap();

        let sk5 = Fr::rand(&mut rng);
        let (_, change5, _) = user5.update_key(&sk5).unwrap();

        let applied_change = change0.clone();
        let all_but_0_changes = vec![
            change2.clone(),
            change3.clone(),
            change4.clone(),
            change5.clone(),
        ];
        let all_changes = vec![change0, change2, change3, change4, change5];

        let root_key_sk = user0.get_root_key().unwrap().key
            + user2.get_root_key().unwrap().key
            + user3.get_root_key().unwrap().key
            + user4.get_root_key().unwrap().key
            + user5.get_root_key().unwrap().key;

        // Check correctness of the merge
        let mut art_def0 = user0.clone();
        art_def0
            .merge_for_participant(applied_change.clone(), &all_but_0_changes, art0.clone())
            .unwrap();

        let mut art_def1 = art1.clone();
        art_def1.merge_for_observer(&all_changes).unwrap();

        assert_eq!(
            art_def0.get_root(),
            art_def1.get_root(),
            "Observer and participant have the same view on the state of the art."
        );

        assert_eq!(
            art_def0.get_root_key().ok(),
            art_def1.get_root_key().ok(),
            "Observer and participant have the same view on the state of the art."
        );

        assert_eq!(
            art_def0, art_def1,
            "Observer and participant have the same view on the state of the art."
        );

        for permutation in all_but_0_changes
            .iter()
            .cloned()
            .permutations(all_but_0_changes.len())
        {
            let mut art_0_analog = user0.clone();
            art_0_analog
                .merge_for_participant(applied_change.clone(), &permutation, art0.clone())
                .unwrap();

            assert_eq!(
                art_0_analog, art_def0,
                "The order of changes applied doesn't affect the result."
            );
        }

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let mut art_1_analog = art1.clone();
            art_1_analog.merge_for_observer(&permutation).unwrap();

            assert_eq!(
                art_1_analog, art_def0,
                "The order of changes applied doesn't affect the result."
            );
        }
    }

    #[test]
    /// Test if art serialization -> deserialization works correctly for unchanged arts
    fn test_art_initial_serialization() {
        init_tracing_for_test();

        let mut rng = StdRng::seed_from_u64(0);

        debug!(
            "Testing art serialization for groups of size from 1 to {}",
            TEST_GROUP_SIZE
        );
        for i in (TEST_GROUP_SIZE - 1)..TEST_GROUP_SIZE {
            // debug!("Test ART serialization for group of size: {}", i);
            let secrets = create_random_secrets::<Fr>(i);

            let (private_art, _) =
                PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

            let serialized_art = private_art.serialize().unwrap();

            // Try to deserialize art for every other user in a group
            for j in 0..i {
                let deserialized_art: PrivateART<CortadoAffine> =
                    PrivateART::deserialize(&serialized_art, &secrets[j]).unwrap();

                assert_eq!(
                    deserialized_art, private_art,
                    "Both users have the same view on the state of the art",
                );
            }
        }
    }

    #[test]
    fn test_art_make_blank() {
        init_tracing_for_test();

        let mut range_rng = rng();
        // let mut rng = StdRng::seed_from_u64(0);
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);

        if TEST_GROUP_SIZE < 4 {
            warn!("Cant run the test, as group size is to small");
            return;
        }

        let combination = (0..TEST_GROUP_SIZE).choose_multiple(&mut range_rng, 2);
        let main_user_id = combination[0];
        let blank_user_id = combination[1];

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        // Create a set of user private arts for tests
        let mut users_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            users_arts.push(
                PrivateART::from_public_art_and_secret(public_art.clone(), secrets[i]).unwrap(),
            );
        }

        // Assert all the users computed the same tree key.
        for i in 0..TEST_GROUP_SIZE {
            assert_eq!(
                users_arts[i], users_arts[0],
                "All the users have the same view on the state of the art"
            );
        }

        // Remove target_user from the art.
        let mut main_user_art = users_arts[main_user_id].clone();
        let target_public_key = CortadoAffine::generator()
            .mul(secrets[blank_user_id])
            .into_affine();
        let temporary_secret = Fr::rand(&mut rng);

        let (root_key, changes, _) = main_user_art
            .make_blank(
                &main_user_art
                    .get_public_art()
                    .get_path_to_leaf(&target_public_key)
                    .unwrap(),
                &temporary_secret,
            )
            .unwrap();

        assert_eq!(main_user_art.get_root_key().unwrap().key, root_key.key);

        // Verify, that all the other users can update the art correctly
        for i in 0..TEST_GROUP_SIZE {
            if i != blank_user_id && i != main_user_id {
                assert_ne!(users_arts[i].get_root_key().unwrap().key, root_key.key);

                users_arts[i].update(&changes).unwrap();
                let user_root_key = users_arts[i].get_root_key().unwrap();

                assert_eq!(user_root_key.key, root_key.key);
                assert_eq!(users_arts[i].get_root().get_weight(), TEST_GROUP_SIZE - 1);
                assert_eq!(users_arts[i], main_user_art)
            }
        }

        // Replace node bask to the previous one, to check if update predicted correctly.
        let new_lambda = Fr::rand(&mut rng);
        let (root_key2, changes2, _) = main_user_art.append_or_replace_node(&new_lambda).unwrap();

        assert_eq!(
            main_user_art.get_secret_key(),
            main_user_art.get_path_secrets()[0],
            "user secret_key is present in path_secrets"
        );
        assert_ne!(root_key2.key, root_key.key);
        for i in 0..TEST_GROUP_SIZE {
            if i != main_user_id && i != blank_user_id {
                users_arts[i].update(&changes2).unwrap();

                assert_eq!(users_arts[i].get_root_key().unwrap().key, root_key2.key);
                assert_eq!(users_arts[i].get_root().get_weight(), TEST_GROUP_SIZE);
            }
        }
    }

    #[test]
    fn test_correctness_of_coordinate_enumeration_in_art() {
        let number_of_users = 32;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(0, 0))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(1, 0))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(1, 1))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(4, 0))
            .unwrap()
            .get_public_key();
        let root_pk = tree
            .get_root()
            .get_left()
            .unwrap()
            .get_left()
            .unwrap()
            .get_left()
            .unwrap()
            .get_left()
            .unwrap()
            .get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(4, 11))
            .unwrap()
            .get_public_key();
        let root_pk = tree
            .get_root()
            .get_right()
            .unwrap()
            .get_left()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(4, 15))
            .unwrap()
            .get_public_key();
        let root_pk = tree
            .get_root()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Coordinate(5, 31))
            .unwrap()
            .get_public_key();
        let root_pk = tree
            .get_root()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_public_key();
        assert!(root_pk.eq(&node_pk));
    }

    #[test]
    fn test_art_node_index_enumeration() {
        let number_of_users = 32;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Index(1))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Index(2))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Index(3))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Index(27))
            .unwrap()
            .get_public_key();
        let root_pk = tree
            .get_root()
            .get_right()
            .unwrap()
            .get_left()
            .unwrap()
            .get_right()
            .unwrap()
            .get_right()
            .unwrap()
            .get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = CortadoAffine::generator().mul(&secrets[2]).into_affine();
        let node_index = NodeIndex::get_index_from_path(
            &tree.get_public_art().get_path_to_leaf(&node_pk).unwrap(),
        )
        .unwrap();
        let rec_node_pk = tree
            .get_public_art()
            .get_node(&NodeIndex::Index(node_index))
            .unwrap()
            .get_public_key();
        assert!(node_pk.eq(&rec_node_pk));
    }

    #[test]
    fn test_art_weight_balance_at_creation() {
        for i in 1..TEST_GROUP_SIZE {
            let secrets = create_random_secrets(i);
            let (art, _) =
                PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
            assert!(get_disbalance(&art).unwrap() < 2);
        }
    }

    #[test]
    fn test_key_update_proof() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test: test_key_update_proof, as group size is to small");
            return;
        }

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[1])
            .expect("Failed to deserialize art");

        let secret_key = art.get_secret_key().clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = vec![2, 3, 4, 5, 6, 7, 8, 9, 10];

        let (tk, key_update_changes, artefacts) = art.update_key(&new_secret_key).unwrap();
        // let (_, artefacts) = art.recompute_root_key_with_artefacts().unwrap();

        assert_eq!(
            art.get_root().get_public_key(),
            CortadoAffine::generator().mul(tk.key).into_affine()
        );

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            test_art
                .get_public_art()
                .compute_artefacts_for_verification(&key_update_changes)
                .unwrap(),
        );

        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn test_make_blank_proof() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test: test_make_blank_proof, as group size is to small");
            return;
        }

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[1])
            .expect("Failed to deserialize art");

        let secret_key = art.get_secret_key().clone();
        let public_key = art.public_key_of(&secret_key);
        let target_public_key = art.public_key_of(&secrets[1]);
        let target_node_path = art
            .get_public_art()
            .get_path_to_leaf(&target_public_key)
            .unwrap();
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = vec![2, 3, 4, 5, 6, 7, 8, 9, 10];

        let (tk, make_blank_changes, artefacts) =
            art.make_blank(&target_node_path, &new_secret_key).unwrap();
        assert_eq!(tk, art.get_root_key().unwrap());

        let verification_artefacts = test_art
            .get_public_art()
            .compute_artefacts_for_verification(&make_blank_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            verification_artefacts,
        );

        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn test_append_node_proof() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test: test_append_node_proof, as group size is to small");
            return;
        }

        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[1])
            .expect("Failed to deserialize art");

        let secret_key = art.get_secret_key().clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = vec![2, 3, 4, 5, 6, 7, 8, 9, 10];

        let (tk, append_node_changes, artefacts) =
            art.append_or_replace_node(&new_secret_key).unwrap();
        assert_eq!(
            art.get_secret_key(),
            art.get_path_secrets()[0],
            "user secret_key is present in path_secrets"
        );
        assert_eq!(tk, art.get_root_key().unwrap());

        let verification_artefacts = test_art
            .get_public_art()
            .compute_artefacts_for_verification(&append_node_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            verification_artefacts,
        );

        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn test_append_node_after_make_blank_proof() {
        let mut rng = StdRng::seed_from_u64(rand::random());
        // Use power of two, so all branches have equal weight. Then any blank node will be the
        // one to be replaced at node addition.
        let art_size = 2usize.pow(7);
        let secrets = create_random_secrets(art_size);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.get_secret_key().clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let associated_data = vec![2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Make blank the node with index 1
        let target_public_key = art.public_key_of(&secrets[1]);
        let target_node_path = art
            .get_public_art()
            .get_path_to_leaf(&target_public_key)
            .unwrap();
        let (_, make_blank_changes, _) =
            art.make_blank(&target_node_path, &new_secret_key).unwrap();
        test_art.update(&make_blank_changes).unwrap();

        let (_, append_node_changes, artefacts) =
            art.append_or_replace_node(&new_secret_key).unwrap();

        let verification_artefacts = test_art
            .get_public_art()
            .compute_artefacts_for_verification(&append_node_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            verification_artefacts,
        );

        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn test_leaf_status_affect_on_make_blank() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let seed = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let (art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let sk_1 = Fr::rand(&mut rng);
        let sk_2 = Fr::rand(&mut rng);
        let user_2_path = art
            .get_public_art()
            .get_path_to_leaf(&CortadoAffine::generator().mul(&secrets[1]).into_affine())
            .unwrap();
        let user_2_index = NodeIndex::from(user_2_path.clone());

        // usual update
        let mut art1 = art.clone();
        art1.make_blank(&user_2_path, &sk_1).unwrap();
        art1.make_blank(&user_2_path, &sk_2).unwrap();
        assert_eq!(
            art1.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art2 = art.clone();
        art2.get_mut_public_art()
            .get_mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::PendingRemoval)
            .unwrap();
        art2.make_blank(&user_2_path, &sk_1).unwrap();
        art2.make_blank(&user_2_path, &sk_2).unwrap();
        assert_eq!(
            art2.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art3 = art.clone();
        art3.get_mut_public_art()
            .get_mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::Blank)
            .unwrap();
        art3.make_blank(&user_2_path, &sk_1).unwrap();
        art3.make_blank(&user_2_path, &sk_2).unwrap();
        assert_eq!(
            art3.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(&(secrets[1] + sk_1 + sk_2))
                .into_affine()
        );
    }

    #[test]
    fn test_leave() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let seed = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let (art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut art2 =
            PrivateART::from_public_art_and_secret(art.get_public_art().clone(), secrets[1])
                .unwrap();

        let art_2_path = art
            .get_public_art()
            .get_path_to_leaf(&CortadoAffine::generator().mul(&secrets[1]).into_affine())
            .unwrap();
        let art_2_index = NodeIndex::from(art_2_path.clone());

        let leave_sk = Fr::rand(&mut rng);
        let (_, leave_change, _) = art2.leave(leave_sk).unwrap();
        assert!(matches!(
            art2.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_status(),
            Some(LeafStatus::PendingRemoval)
        ));
        assert_eq!(
            art2.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(leave_sk)).into_affine()
        );

        let sk_1 = Fr::rand(&mut rng);
        let sk_2 = Fr::rand(&mut rng);

        // usual update
        let mut art1 = art.clone();
        let mut art3 =
            PrivateART::from_public_art_and_secret(art.get_public_art().clone(), secrets[2])
                .unwrap();

        art1.update(&leave_change).unwrap();
        art3.update(&leave_change).unwrap();
        assert_eq!(art1, art3);
        assert!(matches!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_status(),
            Some(LeafStatus::PendingRemoval)
        ));
        assert_eq!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(leave_sk)).into_affine()
        );

        let (_, blank_change1, _) = art1.make_blank(&art_2_path, &sk_1).unwrap();
        art3.update(&blank_change1).unwrap();
        assert_eq!(art1.get_root_key().unwrap(), art3.get_root_key().unwrap());
        assert!(matches!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_status(),
            Some(LeafStatus::Blank)
        ));
        assert_eq!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1)).into_affine()
        );

        let (_, blank_change2, _) = art3.make_blank(&art_2_path, &sk_2).unwrap();
        art1.update(&blank_change2).unwrap();
        assert_eq!(art1, art3);
        assert!(matches!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_status(),
            Some(LeafStatus::Blank)
        ));
        assert_eq!(
            art1.get_public_art()
                .get_node(&art_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        assert_eq!(art1.get_secret_key(), secrets[0]);
    }

    #[test]
    fn test_public_art_merge_for_key_updates() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let seed = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art =
                PrivateART::<CortadoAffine>::from_public_art_and_secret(art.clone(), secrets[i])
                    .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut first = user_arts.remove(0);
        let mut second = user_arts.remove(0);

        let first_secret = create_random_secrets(1)[0];
        let second_secret = create_random_secrets(1)[0];
        let first_public_key = CortadoAffine::generator().mul(first_secret).into_affine();
        let second_public_key = CortadoAffine::generator().mul(second_secret).into_affine();

        let (_, first_changes, _) = first.update_key(&first_secret).unwrap();
        let (_, second_changes, _) = second.update_key(&second_secret).unwrap();

        let first_merged = vec![first_changes.clone()];
        let second_merged = vec![second_changes.clone()];

        let first_clone = first.clone();
        let second_clone = second.clone();
        first
            .get_mut_public_art()
            .merge_with_skip(&first_merged, &vec![second_changes.clone()])
            .unwrap();
        second
            .get_mut_public_art()
            .merge_with_skip(&second_merged, &vec![first_changes.clone()])
            .unwrap();

        assert_eq!(
            first.get_root().get_weight(),
            second.get_root().get_weight()
        );
        assert_eq!(first.get_root(), second.get_root());

        // check leaf update correctness
        assert_eq!(
            first
                .get_public_art()
                .get_node(&first.get_node_index())
                .unwrap()
                .get_public_key(),
            first_public_key
        );
        assert_eq!(
            second
                .get_public_art()
                .get_node(&first.get_node_index())
                .unwrap()
                .get_public_key(),
            first_public_key
        );

        assert_eq!(
            first
                .get_public_art()
                .get_node(&second.get_node_index())
                .unwrap()
                .get_public_key(),
            second_public_key
        );
        assert_eq!(
            second
                .get_public_art()
                .get_node(&second.get_node_index())
                .unwrap()
                .get_public_key(),
            second_public_key
        );

        let all_changes = vec![first_changes.clone(), second_changes.clone()];
        for i in 0..TEST_GROUP_SIZE - 2 {
            user_arts[i]
                .get_mut_public_art()
                .merge_all(&all_changes)
                .unwrap();
            assert_eq!(user_arts[i].get_root(), first.get_root());

            assert_eq!(
                user_arts[i]
                    .get_public_art()
                    .get_node(&first.get_node_index())
                    .unwrap()
                    .get_public_key(),
                first_public_key
            );
            assert_eq!(
                user_arts[i]
                    .get_public_art()
                    .get_node(&second.get_node_index())
                    .unwrap()
                    .get_public_key(),
                second_public_key
            );
        }

        let post_sk = Fr::rand(&mut rng);
        let (_, post_secrets_1, _) = first.update_key(&post_sk).unwrap();

        second.update(&post_secrets_1).unwrap();

        assert_eq!(first, second);

        for i in 0..TEST_GROUP_SIZE - 2 {
            user_arts[i].update(&post_secrets_1).unwrap();

            assert_eq!(user_arts[i], first);
        }
    }

    #[test]
    fn test_merge_for_key_update() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 5 {
            warn!("Cant run the test test_merge_for_add_member, as group size is to small");
            return;
        }

        let mut rng = StdRng::from_seed(rand::random());
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art =
                PrivateART::<CortadoAffine>::from_public_art_and_secret(art.clone(), secrets[i])
                    .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut art1 = user_arts.remove(0);
        let mut art2 = user_arts.remove(1);
        let mut art3 = user_arts.remove(3);
        let mut art4 = user_arts.remove(4);

        let def_art1 = art1.clone();
        let def_art2 = art2.clone();
        let def_art3 = art3.clone();
        let def_art4 = art4.clone();

        assert_eq!(art1.get_root(), art2.get_root());
        assert_eq!(art1.get_root(), art3.get_root());
        assert_eq!(art1.get_root(), art4.get_root());

        let new_node1_sk = Fr::rand(&mut rng);
        let new_node2_sk = Fr::rand(&mut rng);
        let new_node3_sk = Fr::rand(&mut rng);
        let new_node4_sk = Fr::rand(&mut rng);

        let (tk1, changes1, _) = art1.update_key(&new_node1_sk).unwrap();
        let (tk2, changes2, _) = art2.update_key(&new_node2_sk).unwrap();
        let (tk3, changes3, _) = art3.update_key(&new_node3_sk).unwrap();
        let (tk4, changes4, _) = art4.update_key(&new_node4_sk).unwrap();

        // debug!("tk1: {}", tk1.key);
        // debug!("tk2: {}", tk2.key);
        // debug!("tk3: {}", tk3.key);
        // debug!("tk4: {}", tk4.key);

        let merged_tk = ARTRootKey {
            key: tk1.key + tk2.key + tk3.key + tk4.key,
            generator: tk1.generator,
        };

        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&tk1.key)
        );
        assert_eq!(
            art2.get_root().get_public_key(),
            art2.public_key_of(&tk2.key)
        );
        assert_eq!(
            art3.get_root().get_public_key(),
            art3.public_key_of(&tk3.key)
        );
        assert_eq!(
            art4.get_root().get_public_key(),
            art4.public_key_of(&tk4.key)
        );

        assert_eq!(
            art1.get_root().get_public_key(),
            *changes1.public_keys.get(0).unwrap()
        );
        assert_eq!(
            art2.get_root().get_public_key(),
            *changes2.public_keys.get(0).unwrap()
        );
        assert_eq!(
            art3.get_root().get_public_key(),
            *changes3.public_keys.get(0).unwrap()
        );
        assert_eq!(
            art4.get_root().get_public_key(),
            *changes4.public_keys.get(0).unwrap()
        );

        art1.merge_for_participant(
            changes1.clone(),
            &vec![changes2.clone(), changes3.clone(), changes4.clone()],
            def_art1.clone(),
        )
        .unwrap();

        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&merged_tk.key)
        );
        assert_eq!(merged_tk, art1.get_root_key().unwrap());
        let tk1_merged = art1.get_root_key().unwrap();
        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&tk1_merged.key)
        );

        art2.merge_for_participant(
            changes2.clone(),
            &vec![changes1.clone(), changes3.clone(), changes4.clone()],
            def_art2.clone(),
        )
        .unwrap();

        assert_eq!(
            art2.get_root().get_public_key(),
            art2.public_key_of(&merged_tk.key)
        );
        assert_eq!(merged_tk, art2.get_root_key().unwrap());

        let mut root_key_from_changes = CortadoAffine::zero();
        for g in &vec![
            changes1.clone(),
            changes2.clone(),
            changes3.clone(),
            changes4.clone(),
        ] {
            root_key_from_changes = root_key_from_changes.add(g.public_keys[0]).into_affine();
        }
        assert_eq!(root_key_from_changes, art1.public_key_of(&merged_tk.key));
        assert_eq!(root_key_from_changes, art1.get_root().get_public_key());
        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&art1.get_root_key().unwrap().key)
        );

        assert_eq!(
            art1.public_key_of(&new_node1_sk),
            art1.get_public_art()
                .get_node(&art1.get_node_index())
                .unwrap()
                .get_public_key()
        );
        assert_eq!(
            art2.public_key_of(&new_node2_sk),
            art2.get_public_art()
                .get_node(&art2.get_node_index())
                .unwrap()
                .get_public_key()
        );

        assert_eq!(art1, art2);

        let all_changes = vec![changes1, changes2, changes3, changes4];
        for i in 0..TEST_GROUP_SIZE - 4 {
            user_arts[i].merge_for_observer(&all_changes).unwrap();

            let tk = user_arts[i].get_root_key().unwrap();

            assert_eq!(
                root_key_from_changes,
                user_arts[i].get_root().get_public_key()
            );
            assert_eq!(
                user_arts[i].get_root().get_public_key(),
                user_arts[i].public_key_of(&tk.key)
            );
            assert_eq!(merged_tk, user_arts[i].get_root_key().unwrap());
        }

        let post_merge_sk = Fr::rand(&mut rng);
        let (_, post_change, _) = art1.update_key(&post_merge_sk).unwrap();

        art2.update(&post_change).unwrap();

        assert_eq!(art1, art2);

        for i in 0..TEST_GROUP_SIZE - 4 {
            user_arts[i].update(&post_change).unwrap();
            assert_eq!(art1, art2);
        }
    }

    #[test]
    fn test_merge_for_remove_member() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 4 {
            warn!("Cant run the test test_merge_for_remove_member, as the group size is to small");
            return;
        }

        // init test
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art =
                PrivateART::<CortadoAffine>::from_public_art_and_secret(art.clone(), secrets[i])
                    .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        // choose some users for main test subjects
        let mut art1 = user_arts.remove(0);
        let mut art2 = user_arts.remove(1);
        let mut art3 = user_arts.remove(3);

        // Backup previous arts for merge
        let def_art1 = art1.clone();
        let def_art2 = art2.clone();
        let def_art3 = art3.clone();

        // Choose user to remove from the group
        let art4 = user_arts.remove(3);

        // Sanity check
        assert_eq!(art1.get_root(), art2.get_root());
        assert_eq!(art1.get_root(), art3.get_root());
        assert_eq!(art1.get_root(), art4.get_root());

        // Remove the user from the group (make his node blank).
        let new_node1_sk: Fr = Fr::rand(&mut rng);
        let new_node2_sk: Fr = Fr::rand(&mut rng);
        let new_node3_sk: Fr = Fr::rand(&mut rng);

        let target_node_pk = CortadoAffine::generator()
            .mul(&art4.get_secret_key())
            .into_affine();

        let target_node_path = art1
            .get_public_art()
            .get_path_to_leaf(&target_node_pk)
            .unwrap();
        let (tk1, changes1, _) = art1.make_blank(&target_node_path, &new_node1_sk).unwrap();
        let (tk2, changes2, _) = art2.make_blank(&target_node_path, &new_node2_sk).unwrap();
        let (tk3, changes3, _) = art3.make_blank(&target_node_path, &new_node3_sk).unwrap();

        // Compute new tk for tests
        let merged_tk = ARTRootKey {
            key: tk1.key + tk2.key + tk3.key,
            generator: tk1.generator,
        };

        let merged_pub_tk = art1.public_key_of(&merged_tk.key);

        // Sanity check
        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&*art1.get_path_secrets().last().unwrap())
        );
        assert_eq!(
            art2.get_root().get_public_key(),
            art3.public_key_of(&*art2.get_path_secrets().last().unwrap())
        );
        assert_eq!(
            art3.get_root().get_public_key(),
            art4.public_key_of(&*art3.get_path_secrets().last().unwrap())
        );

        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&tk1.key)
        );
        assert_eq!(
            art2.get_root().get_public_key(),
            art2.public_key_of(&tk2.key)
        );
        assert_eq!(
            art3.get_root().get_public_key(),
            art3.public_key_of(&tk3.key)
        );

        assert_eq!(
            art1.get_root().get_public_key(),
            *changes1.public_keys.get(0).unwrap()
        );
        assert_eq!(
            art2.get_root().get_public_key(),
            *changes2.public_keys.get(0).unwrap()
        );
        assert_eq!(
            art3.get_root().get_public_key(),
            *changes3.public_keys.get(0).unwrap()
        );

        // Update art path_secrets with unapplied changes
        art1.merge_for_participant(
            changes1.clone(),
            &vec![changes2.clone(), changes3.clone()],
            def_art1.clone(),
        )
        .unwrap();
        let tk1_merged = art1.get_root_key().unwrap();

        // Check if new tk is correctly computed
        assert_eq!(*art1.get_path_secrets().last().unwrap(), merged_tk.key);
        assert_eq!(merged_tk, tk1_merged);
        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&merged_tk.key)
        );
        assert_eq!(
            art1.get_root().get_public_key(),
            art1.public_key_of(&tk1_merged.key)
        );

        // Update art path_secrets with unapplied changes
        art2.merge_for_participant(
            changes2.clone(),
            &vec![changes1.clone(), changes3.clone()],
            def_art2.clone(),
        )
        .unwrap();

        // Check Merge correctness
        assert_eq!(
            art2.get_root().get_public_key(),
            art2.public_key_of(&merged_tk.key)
        );
        assert_eq!(merged_tk, art2.get_root_key().unwrap());

        assert_eq!(
            art1.public_key_of(&(new_node1_sk + new_node2_sk + new_node3_sk)),
            art1.get_public_art()
                .get_node(&art4.get_node_index())
                .unwrap()
                .get_public_key()
        );
        assert_eq!(
            art2.public_key_of(&(new_node1_sk + new_node2_sk + new_node3_sk)),
            art2.get_public_art()
                .get_node(&art4.get_node_index())
                .unwrap()
                .get_public_key()
        );

        assert_eq!(art1.get_root(), art2.get_root());

        // Check merge correctness for other users
        let all_changes = vec![changes1, changes2, changes3];
        for i in 0..TEST_GROUP_SIZE - 4 {
            user_arts[i].merge_for_observer(&all_changes).unwrap();

            let tk = user_arts[i].get_root_key().unwrap();

            assert_eq!(merged_pub_tk, user_arts[i].get_root().get_public_key());
            assert_eq!(
                user_arts[i].get_root().get_public_key(),
                user_arts[i].public_key_of(&tk.key)
            );
            assert_eq!(merged_tk, user_arts[i].get_root_key().unwrap());
        }
    }

    #[test]
    fn test_merge_for_remove_conflict() {
        init_tracing_for_test();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        if TEST_GROUP_SIZE < 4 {
            warn!("Cant run the test test_merge_for_remove_member, as the group size is to small");
            return;
        }

        // init test
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art =
                PrivateART::<CortadoAffine>::from_public_art_and_secret(art.clone(), secrets[i])
                    .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        // choose some users for main test subjects
        let mut art0 = user_arts.remove(0);
        let mut art1 = user_arts.remove(0);
        let mut art2 = user_arts.remove(1);
        let mut art3 = user_arts.remove(3);
        let mut art4 = user_arts.remove(2);

        // Choose user to remove from the group
        let target_user = user_arts.remove(4);
        let target = target_user.get_node_index().get_path().unwrap();

        let rem_node_sk: Fr = Fr::rand(&mut rng);
        let (tk, change0, artefacts0) = art1.make_blank(&target, &rem_node_sk).unwrap();

        art0.update(&change0).unwrap();
        art2.update(&change0).unwrap();
        art3.update(&change0).unwrap();
        art4.update(&change0).unwrap();

        // Backup previous arts for merge
        let def_art0 = art0.clone();
        let def_art1 = art1.clone();
        let def_art2 = art2.clone();
        let def_art3 = art3.clone();

        // Remove the user from the group (make his node blank).
        let new_node0_sk = Fr::rand(&mut rng);
        let new_node1_sk = Fr::rand(&mut rng);
        let new_node2_sk = Fr::rand(&mut rng);
        let new_node3_sk = Fr::rand(&mut rng);

        let (_, changes0, _) = art0.make_blank(&target, &new_node0_sk).unwrap();
        let (_, changes1, _) = art1.update_key(&new_node1_sk).unwrap();
        let (_, changes2, _) = art2.update_key(&new_node2_sk).unwrap();
        let (_, changes3, _) = art3.make_blank(&target, &new_node3_sk).unwrap();

        let all_changes = vec![
            changes0.clone(),
            changes1.clone(),
            changes2.clone(),
            changes3.clone(),
        ];
        let mut art4_0 = art4.clone();
        art4_0.merge_for_observer(&all_changes).unwrap();
        let mut art1_0 = art1.clone();
        art1_0
            .merge_for_participant(
                changes1.clone(),
                &vec![changes0.clone(), changes2.clone(), changes3.clone()],
                def_art1.clone(),
            )
            .unwrap();

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let mut art_4_analog = art4.clone();
            art_4_analog.merge_for_observer(&permutation).unwrap();

            assert_eq!(
                art4_0, art_4_analog,
                "The order of changes applied doesn't affect the result."
            );

            assert_eq!(
                art4_0
                    .get_public_art()
                    .get_node(target_user.get_node_index())
                    .unwrap()
                    .get_public_key(),
                art4_0.public_key_of(&(new_node0_sk + new_node3_sk + rem_node_sk)),
                "Make blank is correctly merged."
            );
        }

        assert_eq!(art1_0.get_root_key().ok(), art4_0.get_root_key().ok());

        let sk = Fr::rand(&mut rng);
        let (after_merge_tk1, changes1, artefacts1) = art1_0.update_key(&sk).unwrap();

        art4_0.update(&changes1).unwrap();

        assert_eq!(art1_0.get_root_key().ok(), art4_0.get_root_key().ok());
    }

    #[test]
    fn test_merge_for_multi_removal() -> Result<(), ARTError> {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 4 {
            warn!(
                "Can't run the test: test_merge_for_multi_removal, as the group size is too small"
            );
            return Ok(());
        }

        let mut rng = StdRng::seed_from_u64(rand::random());

        // initialize test
        let secrets = create_random_secrets_with_rng(TEST_GROUP_SIZE, &mut rng);
        let (art, _) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art =
                PrivateART::<CortadoAffine>::from_public_art_and_secret(art.clone(), secrets[i])
                    .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        // choose some users for main test subjects
        let mut user0 = user_arts.remove(0);
        let mut user1 = user_arts.remove(0);
        let mut user2 = user_arts.remove(0);
        let user3 = user_arts.remove(0);

        // sanity check
        assert_eq!(user2.get_root(), user0.get_root());
        assert_eq!(user1.get_root(), user0.get_root());
        assert_eq!(user3.get_root(), user0.get_root());

        let target_node_path = user3
            .get_public_art()
            .get_path_to_leaf(&user0.public_key_of(&user3.get_secret_key()))?;
        let target_index = NodeIndex::from(target_node_path.clone());

        let new_node1_sk: Fr = Fr::rand(&mut rng);
        let new_node2_sk: Fr = Fr::rand(&mut rng);
        let new_node3_sk: Fr = Fr::rand(&mut rng);
        let second_key = new_node1_sk + new_node2_sk;
        let final_sk = new_node1_sk + new_node2_sk + new_node3_sk;

        // debug!("User 0 update key ...");
        let (_, change0, _) = user0.make_blank(&target_node_path, &new_node1_sk)?;
        assert_eq!(
            user0
                .get_public_art()
                .get_node(&target_index)?
                .get_public_key(),
            user0.public_key_of(&new_node1_sk)
        );
        assert_eq!(
            user0.public_key_of(&user0.get_root_key()?.key),
            user0.get_root().get_public_key()
        );
        // user0.update_key(None).await?;

        // debug!("User1 receive changes ..");
        // let blank_user_0 = user1.get_changes(20, 0, None).await?;
        user1.update(&change0).unwrap();
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&target_index)?
                .get_public_key(),
            user1.public_key_of(&new_node1_sk)
        );
        assert_eq!(
            user1.public_key_of(&user1.get_root_key()?.key),
            user1.get_root().get_public_key()
        );
        // user1.epoch += 1;
        assert_eq!(user1.get_root(), user0.get_root());

        // debug!("User 1 update key ...");
        let (_, change1, _) = user1.make_blank(&target_node_path, &new_node2_sk)?;
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&target_index)?
                .get_public_key(),
            user1.public_key_of(&second_key)
        );
        assert_eq!(
            user1.public_key_of(&user1.get_root_key()?.key),
            user1.get_root().get_public_key()
        );

        // debug!("User 2 receive changes ...");
        // let blank_user_1 = user2.get_changes(20, 0, None).await?;
        user2.update(&change0).unwrap();
        // user2.epoch += 1;
        // debug!("art2:\n{}", user2.art.get_root());
        assert_eq!(user2.get_root(), user0.get_root());
        assert_eq!(
            user2.public_key_of(&user2.get_root_key()?.key),
            user0.public_key_of(&user0.get_root_key()?.key),
        );

        user2.update(&change1)?;
        assert_eq!(
            user2
                .get_public_art()
                .get_node(&target_index)?
                .get_public_key(),
            user1.public_key_of(&second_key)
        );
        // user2.epoch += 1;
        // debug!("art2:\n{}", user2.art.get_root());
        assert_eq!(user2.get_root(), user1.get_root());
        assert_eq!(
            user2.public_key_of(&user2.get_root_key()?.key),
            user1.public_key_of(&user1.get_root_key()?.key),
        );
        assert_eq!(
            user2.public_key_of(&user2.get_root_key()?.key),
            user1.get_root().get_public_key()
        );

        // debug!("User 2 make blank ...");
        let (_, change2, _) = user2.make_blank(&target_node_path, &new_node3_sk)?;
        Ok(())
    }

    /// Test if non-mergable changes (without blank for the second time) can be aggregated and
    /// applied correctly.
    #[test]
    fn test_branch_aggregation() {
        init_tracing_for_test();

        // Init test context.
        let mut rng: StdRng = StdRng::seed_from_u64(0);
        let secrets = create_random_secrets_with_rng(7, &mut rng);

        let (user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[2]).unwrap();

        let mut user2: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[3]).unwrap();

        let user1_2 = user1.clone();

        let user3: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[4]).unwrap();
        let user4: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secrets[5]).unwrap();

        // Create aggregation
        // let mut agg = ChangeAggregationNode::<ProverAggregationData<CortadoAffine>>::default();
        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);

        let sk1 = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let sk3 = Fr::rand(&mut rng);
        let sk4 = Fr::rand(&mut rng);

        agg.make_blank(
            &user3.get_node_index().get_path().unwrap(),
            &sk1,
            &mut user1,
        )
        .unwrap();

        agg.make_blank(
            &user4.get_node_index().get_path().unwrap(),
            &sk1,
            &mut user1,
        )
        .unwrap();

        agg.append_or_replace_node(&sk2, &mut user1).unwrap();

        agg.append_or_replace_node(&sk3, &mut user1).unwrap();

        agg.append_or_replace_node(&sk4, &mut user1).unwrap();

        // Check successful ProverAggregationTree conversion to tree_ds tree
        let tree_ds_tree = ProverAggregationTree::<CortadoAffine>::try_from(&agg);
        assert!(tree_ds_tree.is_ok());

        for _ in 0..100 {
            let sk_i = Fr::rand(&mut rng);
            agg.append_or_replace_node(&sk_i, &mut user1).unwrap();

            let aggregation = PlainChangeAggregation::try_from(&agg).unwrap();
            let verifier_aggregation = aggregation.add_co_path(&mut user2).unwrap();

            let mut user2_clone = user2.clone();
            verifier_aggregation
                .update_private_art(&mut user2_clone)
                .unwrap();

            assert_eq!(
                user1,
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                user1.get_root(),
                user2_clone.get_root(),
            );
        }

        let root_clone = user1.get_root().clone();
        let leaf_iter = LeafIterWithPath::new(&root_clone).skip(10).take(10);
        for (_, path) in leaf_iter {
            let path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            agg.make_blank(&path, &Fr::rand(&mut rng), &mut user1)
                .unwrap();

            let aggregation = PlainChangeAggregation::try_from(&agg).unwrap();
            let verifier_aggregation = aggregation.add_co_path(&mut user2).unwrap();

            let mut user2_clone = user2.clone();
            verifier_aggregation
                .update_private_art(&mut user2_clone)
                .unwrap();

            assert_eq!(
                user1,
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                user1.get_root(),
                user2_clone.get_root(),
            );
        }

        for i in 0..100 {
            let sk_i = Fr::rand(&mut rng);
            let (_, change_i, _) = agg.append_or_replace_node(&sk_i, &mut user1).unwrap();

            let aggregation = PlainChangeAggregation::try_from(&agg).unwrap();
            let verifier_aggregation = aggregation.add_co_path(&mut user2).unwrap();

            let mut user2_clone = user2.clone();
            verifier_aggregation
                .update_private_art(&mut user2_clone)
                .unwrap();

            assert_eq!(
                user1,
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                user1.get_root(),
                user2_clone.get_root(),
            );
        }

        // Verify structure correctness
        for (node, path) in AggregationNodeIterWithPath::from(&agg) {
            assert_eq!(
                user0.public_key_of(&node.data.secret_key),
                node.data.public_key
            );
            if let Some((parent, _)) = path.last()
                && let Some(co_public_key) = node.data.co_public_key
            {
                let pk = CortadoAffine::generator()
                    .mul(
                        iota_function(&co_public_key.mul(node.data.secret_key).into_affine())
                            .unwrap(),
                    )
                    .into_affine();
                assert_eq!(parent.data.public_key, pk);
            }
        }

        let verifier_aggregation =
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let aggregation_from_prover =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let aggregation_from_verifier =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&verifier_aggregation)
                .unwrap();

        assert_eq!(
            aggregation_from_prover, aggregation_from_verifier,
            "Aggregations are equal from both sources."
        );

        let extracted_verifier_aggregation = aggregation_from_prover.add_co_path(&user2).unwrap();

        assert_eq!(
            verifier_aggregation, extracted_verifier_aggregation,
            "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
            verifier_aggregation, extracted_verifier_aggregation,
        );

        let mut user1_clone = user1_2.clone();
        verifier_aggregation
            .update_private_art(&mut user1_clone)
            .unwrap();
        verifier_aggregation.update_private_art(&mut user2).unwrap();

        assert_eq!(
            user1,
            user1_clone,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_clone\n{}",
            user1.get_root(),
            user1_clone.get_root(),
        );

        assert_eq!(
            user1,
            user2,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser2\n{}",
            user1.get_root(),
            user2.get_root(),
        );
    }

    #[test]
    fn test_branch_aggregation_with_blanking() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = create_random_secrets_with_rng(group_length, &mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();

        let user3_path = user0
            .get_public_art()
            .get_path_to_leaf(&user0.public_key_of(&secrets[4]))
            .unwrap();
        user0.make_blank(&user3_path, &Fr::rand(&mut rng)).unwrap();

        // Create aggregation
        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);

        let sk1 = Fr::rand(&mut rng);

        let result = agg.make_blank(&user3_path, &sk1, &mut user0);

        assert!(
            matches!(result, Err(ARTError::InvalidMergeInput)),
            "Fail to get Error ARTError::InvalidMergeInput. Instead got {:?}.",
            result
        );
    }

    #[test]
    fn test_branch_aggregation_with_leave() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = create_random_secrets_with_rng(group_length, &mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();
        let mut user1 = PrivateART::<CortadoAffine>::from_public_art_and_secret(
            user0.get_public_art().clone(),
            secrets[1],
        )
        .unwrap();

        let target_3 = user0
            .get_public_art()
            .get_path_to_leaf(&user0.public_key_of(&secrets[3]))
            .unwrap();
        // Create aggregation
        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);

        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.make_blank(&target_3, &Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();
        agg.leave(&Fr::rand(&mut rng), &mut user0).unwrap();

        let plain_agg =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let extracted_agg = plain_agg.add_co_path(&user0).unwrap();

        extracted_agg.update_private_art(&mut user1).unwrap();

        assert_eq!(user0, user1);
    }

    #[test]
    fn test_branch_aggregation_proof_verify() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = create_random_secrets_with_rng(group_length, &mut rng);

        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();
        let mut user1 = PrivateART::<CortadoAffine>::from_public_art_and_secret(
            user0.get_public_art().clone(),
            secrets[1],
        )
        .unwrap();

        let target_3 = user0
            .get_public_art()
            .get_path_to_leaf(&user0.public_key_of(&secrets[3]))
            .unwrap();
        // Create aggregation
        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);

        for i in 0..4 {
            agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
                .unwrap();
        }

        let basis = get_pedersen_basis();
        let associated_data = b"data";
        let sk = Fr::rand(&mut rng);
        let pk = user0.public_key_of(&sk);

        let prover_tree = ProverAggregationTree::try_from(&agg).unwrap();

        let proof = art_aggregated_prove(
            basis.clone(),
            associated_data,
            &prover_tree,
            vec![pk],
            vec![sk],
        )
        .unwrap();

        let plain_agg =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let fromed_agg =
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let extracted_agg = plain_agg.add_co_path(&user0).unwrap();
        assert_eq!(
            fromed_agg, extracted_agg,
            "Verifier aggregations are equal from both sources.\nfirst:\n{}\nseccond:\n{}",
            fromed_agg, extracted_agg,
        );

        let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg).unwrap();

        let result = art_aggregated_verify(
            basis.clone(),
            associated_data,
            &verifier_tree,
            vec![pk],
            &proof,
        );

        assert!(result.is_ok());

        extracted_agg.update_private_art(&mut user1).unwrap();

        assert_eq!(user0, user1);
    }

    #[test]
    fn test_branch_aggregation_from_one_node() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![Fr::rand(&mut rng)],
            &CortadoAffine::generator(),
        )
        .unwrap();

        let mut pub_art = user0.get_public_art().clone();

        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();

        agg.update_key(&Fr::rand(&mut rng), &mut user0).unwrap();

        agg.update_key(&Fr::rand(&mut rng), &mut user0).unwrap();

        agg.update_key(&Fr::rand(&mut rng), &mut user0).unwrap();

        let verify_agg =
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(&agg).unwrap();
        let _ = ChangeAggregation::<ProverAggregationData<CortadoAffine>>::try_from(&agg).unwrap();
        let result = verify_agg.update_public_art(&mut pub_art).unwrap();

        assert_eq!(&pub_art, user0.get_public_art())
    }

    #[test]
    fn test_branch_aggregation_for_one_update() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let (mut user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![Fr::rand(&mut rng)],
            &CortadoAffine::generator(),
        )
        .unwrap();

        let mut pub_art = user0.get_public_art().clone();

        let mut prover_rng = thread_rng();
        let mut agg = ProverChangeAggregation::new(&mut prover_rng);
        agg.append_or_replace_node(&Fr::rand(&mut rng), &mut user0)
            .unwrap();

        let verify_agg =
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(&agg).unwrap();
        let _ = ChangeAggregation::<ProverAggregationData<CortadoAffine>>::try_from(&agg).unwrap();
        verify_agg.update_public_art(&mut pub_art).unwrap();

        assert_eq!(
            &pub_art,
            user0.get_public_art(),
            "They are:\n{}\nand\n{}",
            pub_art.get_root(),
            user0.get_public_art().get_root()
        )
    }

    fn create_random_secrets_with_rng<F: Field>(size: usize, rng: &mut StdRng) -> Vec<F> {
        (0..size).map(|_| F::rand(rng)).collect()
    }

    fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        (0..size).map(|_| F::rand(&mut rng)).collect()
    }

    fn min_max_leaf_height(art: &PrivateART<CortadoAffine>) -> Result<(u64, u64), ARTError> {
        let mut min_height = u64::MAX;
        let mut max_height = u64::MIN;
        let root = art.get_root();

        for (_, path) in LeafIterWithPath::new(root) {
            min_height = min(min_height, path.len() as u64);
            max_height = max(max_height, path.len() as u64);
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(art: &PrivateART<CortadoAffine>) -> Result<u64, ARTError> {
        let (min_height, max_height) = min_max_leaf_height(&art)?;

        Ok(max_height - min_height)
    }

    fn get_pedersen_basis() -> PedersenBasis<CortadoAffine, Ed25519Affine> {
        let g_1 = CortadoAffine::generator();
        let h_1 = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);

        let gens = PedersenGens::default();
        PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
            g_1,
            h_1,
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        )
    }

    fn check_art_proof_and_verify(
        associated_data: &[u8],
        aux_sk: Vec<Fr>,
        aux_pk: Vec<CortadoAffine>,
        artefacts: ProverArtefacts<CortadoAffine>,
        verification_artefacts: VerifierArtefacts<CortadoAffine>,
    ) -> Result<(), R1CSError> {
        let basis = get_pedersen_basis();

        let proof = art_prove(
            basis.clone(),
            associated_data,
            &artefacts.to_prover_branch(&mut thread_rng()).unwrap(),
            aux_pk.clone(),
            aux_sk,
        )?;

        art_verify(
            basis.clone(),
            associated_data,
            &verification_artefacts.to_verifier_branch().unwrap(),
            aux_pk,
            proof.clone(),
        )
    }
}
