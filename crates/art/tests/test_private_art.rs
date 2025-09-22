mod utils;

#[cfg(test)]
mod tests {
    use super::utils::init_tracing_for_test;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::EdwardsAffine as Ed25519Affine;
    use ark_ff::{BigInteger, Field, PrimeField};
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use ark_std::{One, UniformRand, Zero};
    use art::helper_tools::{to_ark_scalar, to_dalek_scalar};
    use art::traits::ARTPrivateView;
    use art::types::{
        ARTRootKey, BranchChanges, LeafIterWithPath, NodeIndex, ProverArtefacts, VerifierArtefacts,
    };
    use art::{
        errors::ARTError,
        traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
        types::{PrivateART, PublicART},
    };
    use bulletproofs::PedersenGens;
    use bulletproofs::r1cs::R1CSError;
    use cortado::{CortadoAffine, Fr};
    use curve25519_dalek::Scalar;
    use rand::{Rng, rng};
    use std::cmp::{max, min};
    use std::ops::{Add, Mul};
    use tracing::field::debug;
    use tracing::{debug, warn};
    use zk::art::{art_prove, art_verify};
    use zkp::toolbox::cross_dleq::PedersenBasis;
    use zkp::toolbox::dalek_ark::ristretto255_to_ark;

    pub const TEST_GROUP_SIZE: usize = 100;

    /// User creates art with one node and appends new user. New user updates his sk.
    #[test]
    fn test_flow1() {
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
            user0.get_node(&changes.node_index).unwrap().public_key,
            user0.public_key_of(&secret_key_1),
            "New node is in the art, and it is on the correct path.",
        );
        assert_eq!(
            user0.get_node(&user0.node_index).unwrap().public_key,
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
            user0.get_node(&changes.node_index).unwrap().public_key,
            user0.get_node(&user0.node_index).unwrap().public_key,
            "Sanity check: Both users nodes have different public key.",
        );

        // Serialise and deserialize art for the new user.
        let public_art_bytes = user0.serialize().unwrap();
        assert_ne!(secret_key_0, secret_key_1);
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        assert_ne!(
            user0.path_secrets, user1.path_secrets,
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

        user0.update_private_art(&change_key_update).unwrap();

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

    /// main user creates art with three users, then removes one of them. The remaining user
    /// updates his art, and also removes user (instead or changing, he utilizes merge). Removed
    /// user fails to update his art.
    #[test]
    fn test_flow2() {
        init_tracing_for_test();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        assert_ne!(secret_key_1, secret_key_2);

        let (mut user0, def_tk) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &vec![secret_key_0, secret_key_1, secret_key_2],
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = user0.serialize().unwrap();
        let mut user1: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_1).unwrap();

        let mut user2: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &secret_key_2).unwrap();

        assert_ne!(
            user0.path_secrets, user1.path_secrets,
            "Sanity check: Both users have different path secrets"
        );
        assert_ne!(
            user0.path_secrets, user2.path_secrets,
            "Sanity check: Both users have different path secrets"
        );
        assert_ne!(
            user2.path_secrets, user1.path_secrets,
            "Sanity check: Both users have different path secrets"
        );
        assert!(user0.eq(&user1), "New user received the same art");
        assert!(user0.eq(&user2), "New user received the same art");

        let tk0 = user0.get_root_key().unwrap();
        let tk1 = user1.get_root_key().unwrap();
        let tk2 = user2.get_root_key().unwrap();

        let blanking_secret_key_1 = Fr::rand(&mut rng);
        let blanking_secret_key_2 = Fr::rand(&mut rng);

        // User0 removes second user node from the art.
        let (tk_r1, remove_member_change1, _) = user0
            .make_blank(
                &user2.node_index.get_path().unwrap(),
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
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .public_key,
            user0.public_key_of(&blanking_secret_key_1),
            "The node was removed correctly."
        );

        // Sync other users art
        user1.update_private_art(&remove_member_change1).unwrap();

        assert!(
            matches!(
                user2.update_private_art(&remove_member_change1).err(),
                Some(ARTError::InapplicableBlanking)
            ),
            "Cant perform art update using blank leaf."
        );

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .public_key,
            user1.public_key_of(&blanking_secret_key_1),
            "The node was removed correctly."
        );

        // User1 removes second user node from the art.
        let (tk_r2, remove_member_change2, _) = user1
            .make_blank(
                &user2.node_index.get_path().unwrap(),
                &blanking_secret_key_2,
            )
            .unwrap();
        assert_eq!(
            user1
                .get_node(&remove_member_change2.node_index)
                .unwrap()
                .public_key,
            user1.public_key_of(&(blanking_secret_key_1 + blanking_secret_key_2)),
            "The node was removed correctly."
        );
        assert_eq!(
            user1.get_root().public_key,
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
        user0.update_private_art(&remove_member_change2).unwrap();

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .public_key,
            user1.public_key_of(&(blanking_secret_key_1 + blanking_secret_key_2)),
            "The node was removed correctly."
        );
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
            users_arts.push(PrivateART::from_public_art(public_art.clone(), secrets[i]).unwrap());
        }

        for i in 0..TEST_GROUP_SIZE {
            // Assert creator and users computed the same tree key.
            assert_eq!(users_arts[i].get_root_key().unwrap().key, root_key.key);
        }

        let mut main_user_art = users_arts[main_user_id].clone();

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = get_random_scalar_with_rng(&mut rng);
        let (new_key, changes, _) = main_user_art.update_key(&main_new_key).unwrap();

        assert_ne!(new_key.key, main_old_key);

        users_arts[72].update_private_art(&changes).unwrap();
        assert_eq!(users_arts[72].get_root_key().unwrap().key, new_key.key);
        assert_eq!(new_key, users_arts[72].get_root_key().unwrap());

        // for i in 0..TEST_GROUP_SIZE {
        //     if i != main_user_id {
        //         users_arts[i].update_private_art(&changes).unwrap();
        //         debug!("I: {}", i);
        //         assert_eq!(users_arts[i].get_root_key().unwrap().key, new_key.key);
        //         assert_eq!(new_key, users_arts[i].get_root_key().unwrap());
        //     }
        // }

        let (recomputed_old_key, changes, _) = main_user_art.update_key(&main_old_key).unwrap();

        assert_eq!(root_key.key, recomputed_old_key.key);

        for i in 0..TEST_GROUP_SIZE {
            if i != main_user_id {
                users_arts[i].update_private_art(&changes).unwrap();
                assert_eq!(
                    users_arts[i].get_root_key().unwrap().key,
                    recomputed_old_key.key
                );
                assert_eq!(recomputed_old_key, users_arts[i].get_root_key().unwrap());
            }
        }
    }

    #[test]
    fn test_get_public_art() {
        let secrets = create_random_secrets(TEST_GROUP_SIZE);

        let (mut private_art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let public_art = PublicART::from(private_art);
    }

    #[test]
    fn test_art_weights_correctness() {
        let secrets = create_random_secrets(TEST_GROUP_SIZE);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 1..TEST_GROUP_SIZE {
            let _ = tree.append_or_replace_node(&Fr::rand(&mut rng)).unwrap();
        }

        for node in tree.get_root() {
            if node.is_leaf() {
                if node.is_blank {
                    assert_eq!(node.weight, 0);
                } else {
                    assert_eq!(node.weight, 1);
                }
            } else {
                assert_eq!(
                    node.weight,
                    node.get_left().unwrap().weight + node.get_right().unwrap().weight
                );
            }
        }
    }

    #[test]
    fn test_art_tree_serialization() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test: test_art_tree_serialization, as group size is to small");
            return;
        }

        let secrets = create_random_secrets(TEST_GROUP_SIZE);

        let (tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let serialized = tree.serialize().unwrap();
        let deserialized: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&serialized, &secrets[1]).unwrap();

        assert!(
            deserialized
                .get_root()
                .public_key
                .eq(&tree.get_root().public_key)
        );
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

        let main_user_id = range_rng.random_range(0..(TEST_GROUP_SIZE - 2));
        let mut blank_user_id = range_rng.random_range(0..(TEST_GROUP_SIZE - 3));
        while blank_user_id >= main_user_id && blank_user_id <= main_user_id + 2 {
            blank_user_id = range_rng.random_range(0..(TEST_GROUP_SIZE - 3));
        }

        // let mut rng = StdRng::seed_from_u64(rand::random());

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut users_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            users_arts.push(PrivateART::from_public_art(public_art.clone(), secrets[i]).unwrap());
        }

        for i in 0..TEST_GROUP_SIZE {
            // Assert all the users computed the same tree key.
            assert_eq!(users_arts[i].get_root_key().unwrap().key, root_key.key);
        }

        let mut main_user_art = users_arts[main_user_id].clone();
        let target_public_key = CortadoAffine::generator()
            .mul(secrets[blank_user_id])
            .into_affine();
        let temporary_secret = Fr::rand(&mut rng);

        let (root_key, changes, _) = main_user_art
            .make_blank(
                &main_user_art.get_path_to_leaf(&target_public_key).unwrap(),
                &temporary_secret,
            )
            .unwrap();

        assert_eq!(main_user_art.get_root_key().unwrap().key, root_key.key);

        for i in 0..TEST_GROUP_SIZE {
            if i != blank_user_id && i != main_user_id {
                assert_ne!(users_arts[i].get_root_key().unwrap().key, root_key.key);

                users_arts[i].update_private_art(&changes).unwrap();
                let user_root_key = users_arts[i].get_root_key().unwrap();

                assert_eq!(user_root_key.key, root_key.key);
                assert_eq!(users_arts[i].get_root().weight, TEST_GROUP_SIZE - 1);
            }
        }

        let new_lambda = Fr::rand(&mut rng);

        let (root_key2, changes2, _) = main_user_art.append_or_replace_node(&new_lambda).unwrap();

        assert_ne!(root_key2.key, root_key.key);

        for i in 0..TEST_GROUP_SIZE {
            if i != main_user_id && i != blank_user_id {
                users_arts[i].update_private_art(&changes2).unwrap();

                assert_eq!(users_arts[i].get_root_key().unwrap().key, root_key2.key);
                assert_eq!(users_arts[i].get_root().weight, TEST_GROUP_SIZE);
            }
        }
    }

    #[test]
    fn test_art_node_coordinate_enumeration() {
        let number_of_users = 32;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let node_pk = tree
            .get_node(&NodeIndex::Coordinate(0, 0))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_node(&NodeIndex::Coordinate(1, 0))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_node(&NodeIndex::Coordinate(1, 1))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
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
            .get_node(&NodeIndex::Index(1))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_node(&NodeIndex::Index(2))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
            .get_node(&NodeIndex::Index(3))
            .unwrap()
            .get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree
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
        let node_index = tree.get_leaf_index(&node_pk).unwrap();
        let rec_node_pk = tree
            .get_node(&NodeIndex::Index(node_index))
            .unwrap()
            .get_public_key();
        assert!(node_pk.eq(&rec_node_pk));
    }

    #[test]
    fn art_balance_at_creation() {
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

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (tk, key_update_changes, artefacts) = art.update_key(&new_secret_key).unwrap();
        // let (_, artefacts) = art.recompute_root_key_with_artefacts().unwrap();

        assert_eq!(
            art.root.public_key,
            CortadoAffine::generator().mul(tk.key).into_affine()
        );

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            key_update_changes.clone(),
            test_art
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

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let target_public_key = art.public_key_of(&secrets[1]);
        let target_node_path = art.get_path_to_leaf(&target_public_key).unwrap();
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (tk, make_blank_changes, artefacts) =
            art.make_blank(&target_node_path, &new_secret_key).unwrap();
        assert_eq!(tk, art.get_root_key().unwrap());
        // let (_, artefacts) = art
        //     .recompute_root_key_with_artefacts_using_secret_key(
        //         new_secret_key,
        //         Some(&make_blank_changes.node_index),
        //     )
        //     .unwrap();

        let verification_artefacts = test_art
            .compute_artefacts_for_verification(&make_blank_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            make_blank_changes,
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

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (tk, append_node_changes, artefacts) =
            art.append_or_replace_node(&new_secret_key).unwrap();
        assert_eq!(tk, art.get_root_key().unwrap());
        let (_, artefacts_rl) = art
            .recompute_root_key_with_artefacts_using_secret_key(
                new_secret_key,
                &append_node_changes.node_index,
            )
            .unwrap();
        assert_eq!(artefacts.co_path, artefacts_rl.co_path);
        assert_eq!(artefacts.path, artefacts_rl.path);
        assert_eq!(artefacts.secrets, artefacts_rl.secrets);

        let verification_artefacts = test_art
            .compute_artefacts_for_verification(&append_node_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            append_node_changes,
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

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        // Make blank the node with index 1
        let target_public_key = art.public_key_of(&secrets[1]);
        let target_node_path = art.get_path_to_leaf(&target_public_key).unwrap();
        let (_, make_blank_changes, _) =
            art.make_blank(&target_node_path, &new_secret_key).unwrap();
        test_art.update_private_art(&make_blank_changes).unwrap();

        let (_, append_node_changes, artefacts) =
            art.append_or_replace_node(&new_secret_key).unwrap();

        let verification_artefacts = test_art
            .compute_artefacts_for_verification(&append_node_changes)
            .unwrap();

        let verification_result = check_art_proof_and_verify(
            associated_data.as_slice(),
            vec![secret_key],
            vec![public_key],
            artefacts,
            append_node_changes,
            verification_artefacts,
        );

        assert_eq!(verification_result, Ok(()));
    }

    #[test]
    fn test_merge_for_key_updates() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art = PrivateART::<CortadoAffine>::try_from((art.clone(), secrets[i]))
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
        first.merge_change(&first_merged, &second_changes).unwrap();
        second.merge_change(&second_merged, &first_changes).unwrap();

        assert_eq!(first.root.weight, second.root.weight);
        // debug!("first:\n{}", first.root);
        // debug!("second:\n{}", second.root);
        assert_eq!(first.root, second.root);

        // check leaf update correctness
        assert_eq!(
            first.get_node(&first.node_index).unwrap().public_key,
            first_public_key
        );
        assert_eq!(
            second.get_node(&first.node_index).unwrap().public_key,
            first_public_key
        );

        assert_eq!(
            first.get_node(&second.node_index).unwrap().public_key,
            second_public_key
        );
        assert_eq!(
            second.get_node(&second.node_index).unwrap().public_key,
            second_public_key
        );

        let mut rng = rand::rng();
        for i in 0..TEST_GROUP_SIZE - 2 {
            match rng.random_bool(0.5) {
                true => {
                    user_arts[i].update_private_art(&first_changes).unwrap();
                    user_arts[i]
                        .merge_change(&first_merged, &second_changes)
                        .unwrap();
                }
                false => {
                    user_arts[i].update_private_art(&second_changes).unwrap();
                    user_arts[i]
                        .merge_change(&second_merged, &first_changes)
                        .unwrap();
                }
            }

            assert_eq!(user_arts[i].root, first.root);

            assert_eq!(
                user_arts[i].get_node(&first.node_index).unwrap().public_key,
                first_public_key
            );
            assert_eq!(
                user_arts[i]
                    .get_node(&second.node_index)
                    .unwrap()
                    .public_key,
                second_public_key
            );
        }
    }

    #[test]
    fn test_general_merge_for_key_updates() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_remove_member, as the group size is to small");
            return;
        }

        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art = PrivateART::<CortadoAffine>::try_from((art.clone(), secrets[i]))
                .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut first = user_arts.remove(0);
        let mut second = user_arts.remove(0);

        let first_secret = create_random_secrets(1)[0];
        let second_secret = create_random_secrets(1)[0];
        let first_public_key = CortadoAffine::generator().mul(first_secret).into_affine();
        let second_public_key = CortadoAffine::generator().mul(second_secret).into_affine();

        let (tk1, first_changes, _) = first.update_key(&first_secret).unwrap();
        let (tk2, second_changes, _) = second.update_key(&second_secret).unwrap();

        let first_merged = vec![first_changes.clone()];
        let second_merged = vec![second_changes.clone()];

        let first_clone = first.clone();
        let second_clone = second.clone();
        first.merge_change(&first_merged, &second_changes).unwrap();
        second.merge_change(&second_merged, &first_changes).unwrap();

        assert_eq!(
            first.root.public_key,
            first.public_key_of(&(tk1.key + tk2.key))
        );
        assert_eq!(
            second.root.public_key,
            first.public_key_of(&(tk1.key + tk2.key))
        );

        assert_eq!(first.root.weight, second.root.weight);
        // debug!("first:\n{}", first.root);
        // debug!("second:\n{}", second.root);
        assert_eq!(first.root, second.root);

        // check leaf update correctness
        assert_eq!(
            first.get_node(&first.node_index).unwrap().public_key,
            first_public_key
        );
        assert_eq!(
            second.get_node(&first.node_index).unwrap().public_key,
            first_public_key
        );

        assert_eq!(
            first.get_node(&second.node_index).unwrap().public_key,
            second_public_key
        );
        assert_eq!(
            second.get_node(&second.node_index).unwrap().public_key,
            second_public_key
        );

        let all_changes = vec![first_changes, second_changes];
        let mut root_key_from_changes = CortadoAffine::zero();
        for g in &all_changes {
            root_key_from_changes = root_key_from_changes.add(g.public_keys[0]).into_affine();
        }
        assert_ne!(root_key_from_changes, CortadoAffine::zero());
        let mut rng = rand::rng();
        for i in 0..TEST_GROUP_SIZE - 2 {
            match rng.random_bool(0.5) {
                true => {
                    user_arts[i].merge(&all_changes).unwrap();
                }
                false => {
                    user_arts[i].merge(&all_changes).unwrap();
                }
            }

            assert_eq!(user_arts[i].root, first.root);

            assert_eq!(
                user_arts[i].get_node(&first.node_index).unwrap().public_key,
                first_public_key
            );
            assert_eq!(
                user_arts[i]
                    .get_node(&second.node_index)
                    .unwrap()
                    .public_key,
                second_public_key
            );
            assert_eq!(user_arts[i].get_root().public_key, root_key_from_changes);
            assert_eq!(
                user_arts[i].root.public_key,
                user_arts[i].public_key_of(&(tk1.key + tk2.key))
            );
        }
    }

    #[test]
    fn test_merge_for_add_member() {
        init_tracing_for_test();

        if TEST_GROUP_SIZE < 5 {
            warn!("Cant run the test test_merge_for_add_member, as group size is to small");
            return;
        }

        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art = PrivateART::<CortadoAffine>::try_from((art.clone(), secrets[i]))
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

        assert_eq!(art1.root, art2.root);
        assert_eq!(art1.root, art3.root);
        assert_eq!(art1.root, art4.root);

        let new_node1_sk = create_random_secrets(1)[0];
        let new_node2_sk = create_random_secrets(1)[0];
        let new_node3_sk = create_random_secrets(1)[0];
        let new_node4_sk = create_random_secrets(1)[0];

        let (tk1, changes1, _) = art1.update_key(&new_node1_sk).unwrap();
        let (tk2, changes2, _) = art2.update_key(&new_node2_sk).unwrap();
        let (tk3, changes3, _) = art3.update_key(&new_node3_sk).unwrap();
        let (tk4, changes4, _) = art4.update_key(&new_node4_sk).unwrap();

        let merged_tk = ARTRootKey {
            key: tk1.key + tk2.key + tk3.key + tk4.key,
            generator: tk1.generator,
        };

        assert_eq!(art1.root.public_key, art1.public_key_of(&tk1.key));
        assert_eq!(art2.root.public_key, art2.public_key_of(&tk2.key));
        assert_eq!(art3.root.public_key, art3.public_key_of(&tk3.key));
        assert_eq!(art4.root.public_key, art4.public_key_of(&tk4.key));

        assert_eq!(art1.root.public_key, *changes1.public_keys.get(0).unwrap());
        assert_eq!(art2.root.public_key, *changes2.public_keys.get(0).unwrap());
        assert_eq!(art3.root.public_key, *changes3.public_keys.get(0).unwrap());
        assert_eq!(art4.root.public_key, *changes4.public_keys.get(0).unwrap());

        art1.recompute_path_secrets_for_participant(
            &vec![changes2.clone(), changes3.clone(), changes4.clone()],
            &def_art1,
        )
        .unwrap();
        art1.merge_with_skip(
            &vec![changes1.clone()],
            &vec![changes2.clone(), changes3.clone(), changes4.clone()],
        )
        .unwrap();
        art1.update_node_index().unwrap();
        assert_eq!(art1.root.public_key, art1.public_key_of(&merged_tk.key));
        assert_eq!(merged_tk, art1.get_root_key().unwrap());
        let tk1_merged = art1.get_root_key().unwrap();
        assert_eq!(art1.root.public_key, art1.public_key_of(&tk1_merged.key));

        art2.recompute_path_secrets_for_participant(
            &vec![changes1.clone(), changes3.clone(), changes4.clone()],
            &def_art2,
        )
        .unwrap();
        art2.merge_with_skip(
            &vec![changes2.clone()],
            &vec![changes1.clone(), changes3.clone(), changes4.clone()],
        )
        .unwrap();
        art2.update_node_index().unwrap();
        assert_eq!(art2.root.public_key, art2.public_key_of(&merged_tk.key));
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
        assert_eq!(root_key_from_changes, art1.root.public_key);
        assert_eq!(
            art1.root.public_key,
            art1.public_key_of(&art1.get_root_key().unwrap().key)
        );

        assert_eq!(
            art1.public_key_of(&new_node1_sk),
            art1.get_node(&art1.node_index).unwrap().public_key
        );
        assert_eq!(
            art2.public_key_of(&new_node2_sk),
            art2.get_node(&art2.node_index).unwrap().public_key
        );

        assert_eq!(art1.root, art2.root);

        let all_changes = vec![changes1, changes2, changes3, changes4];
        for i in 0..TEST_GROUP_SIZE - 4 {
            user_arts[i]
                .recompute_path_secrets_for_observer(&all_changes)
                .unwrap();
            user_arts[i].merge(&all_changes).unwrap();

            let tk = user_arts[i].get_root_key().unwrap();

            assert_eq!(root_key_from_changes, user_arts[i].root.public_key);
            assert_eq!(
                user_arts[i].root.public_key,
                user_arts[i].public_key_of(&tk.key)
            );
            assert_eq!(merged_tk, user_arts[i].get_root_key().unwrap());
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
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art = PrivateART::<CortadoAffine>::try_from((art.clone(), secrets[i]))
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
        let art4 = user_arts.remove(4);

        // Sanity check
        assert_eq!(art1.root, art2.root);
        assert_eq!(art1.root, art3.root);
        assert_eq!(art1.root, art4.root);

        // Remove the user from the group (make his node blank).
        let new_node1_sk: Fr = create_random_secrets(1)[0];
        let new_node2_sk: Fr = create_random_secrets(1)[0];
        let new_node3_sk: Fr = create_random_secrets(1)[0];

        let target_node_pk = CortadoAffine::generator()
            .mul(&art4.secret_key)
            .into_affine();

        let target_node_path = art1.get_path_to_leaf(&target_node_pk).unwrap();
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
            art1.root.public_key,
            art1.public_key_of(&*art1.path_secrets.last().unwrap())
        );
        assert_eq!(
            art2.root.public_key,
            art3.public_key_of(&*art2.path_secrets.last().unwrap())
        );
        assert_eq!(
            art3.root.public_key,
            art4.public_key_of(&*art3.path_secrets.last().unwrap())
        );

        assert_eq!(art1.root.public_key, art1.public_key_of(&tk1.key));
        assert_eq!(art2.root.public_key, art2.public_key_of(&tk2.key));
        assert_eq!(art3.root.public_key, art3.public_key_of(&tk3.key));

        assert_eq!(art1.root.public_key, *changes1.public_keys.get(0).unwrap());
        assert_eq!(art2.root.public_key, *changes2.public_keys.get(0).unwrap());
        assert_eq!(art3.root.public_key, *changes3.public_keys.get(0).unwrap());

        // Update art path_secrets with unapplied changes
        art1.recompute_path_secrets_for_participant(
            &vec![changes2.clone(), changes3.clone()],
            &def_art1,
        )
        .unwrap();

        // Check if new tk is correctly computed
        assert_eq!(*art1.path_secrets.last().unwrap(), merged_tk.key);

        // Merge unapplied changes into the art
        art1.merge_with_skip(
            &vec![changes1.clone()],
            &vec![changes2.clone(), changes3.clone()],
        )
        .unwrap();

        // Check Merge correctness
        let tk1_merged = art1.get_root_key().unwrap();
        assert_eq!(art1.root.public_key, art1.public_key_of(&merged_tk.key));
        assert_eq!(merged_tk, tk1_merged);
        assert_eq!(art1.root.public_key, art1.public_key_of(&tk1_merged.key));

        // Update art path_secrets with unapplied changes
        art2.recompute_path_secrets_for_participant(
            &vec![changes1.clone(), changes3.clone()],
            &def_art2,
        )
        .unwrap();
        // Merge unapplied changes into the art
        art2.merge_with_skip(
            &vec![changes2.clone()],
            &vec![changes1.clone(), changes3.clone()],
        )
        .unwrap();

        // Check Merge correctness
        assert_eq!(art2.root.public_key, art2.public_key_of(&merged_tk.key));
        assert_eq!(merged_tk, art2.get_root_key().unwrap());

        assert_eq!(
            art1.public_key_of(&(new_node1_sk + new_node2_sk + new_node3_sk)),
            art1.get_node(&art4.node_index).unwrap().public_key
        );
        assert_eq!(
            art2.public_key_of(&(new_node1_sk + new_node2_sk + new_node3_sk)),
            art2.get_node(&art4.node_index).unwrap().public_key
        );

        assert_eq!(art1.root, art2.root);

        // Check merge correctness for other users
        let all_changes = vec![changes1, changes2, changes3];
        for i in 0..TEST_GROUP_SIZE - 4 {
            user_arts[i]
                .recompute_path_secrets_for_observer(&all_changes)
                .unwrap();
            user_arts[i].merge(&all_changes).unwrap();

            let tk = user_arts[i].get_root_key().unwrap();

            assert_eq!(merged_pub_tk, user_arts[i].root.public_key);
            assert_eq!(
                user_arts[i].root.public_key,
                user_arts[i].public_key_of(&tk.key)
            );
            assert_eq!(merged_tk, user_arts[i].get_root_key().unwrap());
        }
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
        let secrets = create_random_secrets(TEST_GROUP_SIZE);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..TEST_GROUP_SIZE {
            let art = PrivateART::<CortadoAffine>::try_from((art.clone(), secrets[i]))
                .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        // choose some users for main test subjects
        let mut user0 = user_arts.remove(0);
        let mut user1 = user_arts.remove(0);
        let mut user2 = user_arts.remove(0);
        let mut user3 = user_arts.remove(0);

        // sanity check
        assert_eq!(user2.get_root(), user0.get_root());
        assert_eq!(user1.get_root(), user0.get_root());
        assert_eq!(user3.get_root(), user0.get_root());

        let target_node_path = user3.get_path_to_leaf(&user0.public_key_of(&user3.secret_key))?;
        let target_index = NodeIndex::from(target_node_path.clone());

        let new_node1_sk: Fr = create_random_secrets(1)[0];
        let new_node2_sk: Fr = create_random_secrets(1)[0];
        let new_node3_sk: Fr = create_random_secrets(1)[0];
        let second_key = new_node1_sk + new_node2_sk;
        let final_sk = new_node1_sk + new_node2_sk + new_node3_sk;

        debug!("User 0 update key ...");
        let (_, change0, _) = user0.make_blank(&target_node_path, &new_node1_sk)?;
        assert_eq!(
            user0.get_node(&target_index)?.public_key,
            user0.public_key_of(&new_node1_sk)
        );
        assert_eq!(
            user0.public_key_of(&user0.get_root_key()?.key),
            user0.get_root().public_key
        );
        // user0.update_key(None).await?;

        debug!("User1 receive changes ..");
        // let blank_user_0 = user1.get_changes(20, 0, None).await?;
        user1.update_private_art(&change0).unwrap();
        assert_eq!(
            user1.get_node(&target_index)?.public_key,
            user1.public_key_of(&new_node1_sk)
        );
        assert_eq!(
            user1.public_key_of(&user1.get_root_key()?.key),
            user1.get_root().public_key
        );
        // user1.epoch += 1;
        assert_eq!(user1.get_root(), user0.get_root());

        debug!("User 1 update key ...");
        let (_, change1, _) = user1.make_blank(&target_node_path, &new_node2_sk)?;
        assert_eq!(
            user1.get_node(&target_index)?.public_key,
            user1.public_key_of(&second_key)
        );
        assert_eq!(
            user1.public_key_of(&user1.get_root_key()?.key),
            user1.get_root().public_key
        );

        debug!("User 2 receive changes ...");
        // let blank_user_1 = user2.get_changes(20, 0, None).await?;
        user2.update_private_art(&change0).unwrap();
        // user2.epoch += 1;
        // debug!("art2:\n{}", user2.art.get_root());
        assert_eq!(user2.get_root(), user0.get_root());
        assert_eq!(
            user2.public_key_of(&user2.get_root_key()?.key),
            user0.public_key_of(&user0.get_root_key()?.key),
        );

        user2.update_private_art(&change1)?;
        assert_eq!(
            user2.get_node(&target_index)?.public_key,
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
            user1.get_root().public_key
        );

        debug!("User 2 make blank ...");
        let (_, change2, _) = user2.make_blank(&target_node_path, &new_node3_sk)?;
        Ok(())
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

    fn get_random_scalar_with_rng(rng: &mut StdRng) -> Fr {
        let mut k = Fr::zero();
        while k.is_one() || k.is_zero() {
            k = Fr::rand(rng);
        }

        k
    }

    #[inline]
    fn new_blindings(size: usize) -> Vec<Scalar> {
        (0..size)
            .map(|_| Scalar::random(&mut thread_rng()))
            .collect()
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
        update_changes: BranchChanges<CortadoAffine>,
        verification_artefacts: VerifierArtefacts<CortadoAffine>,
    ) -> Result<(), R1CSError> {
        let basis = get_pedersen_basis();

        let proof = art_prove(
            basis.clone(),
            associated_data,
            aux_pk.clone(),
            artefacts.path.clone(),
            artefacts.co_path.clone(),
            artefacts.secrets.clone(),
            aux_sk,
            new_blindings(artefacts.co_path.len() + 1),
        )?;

        art_verify(
            basis.clone(),
            associated_data,
            aux_pk,
            verification_artefacts.path,
            verification_artefacts.co_path,
            proof.clone(),
        )
    }
}
