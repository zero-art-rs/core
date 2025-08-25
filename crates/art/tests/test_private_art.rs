#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::EdwardsAffine as Ed25519Affine;
    use ark_ff::Field;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use ark_std::{One, UniformRand, Zero};
    use art::types::{
        BranchChanges, BranchChangesType, LeafIterWithPath, NodeIndex, ProverArtefacts,
        VerifierArtefacts,
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
    use std::ops::Mul;
    use tracing::info;
    use zk::art::{art_prove, art_verify};
    use zkp::toolbox::cross_dleq::PedersenBasis;
    use zkp::toolbox::dalek_ark::ristretto255_to_ark;

    #[test]
    fn test_art_key_update() {
        let number_of_users = 100;
        let main_user_id = rng().random_range(0..number_of_users);
        let secrets = create_random_secrets(number_of_users);

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut users_arts = Vec::new();
        for i in 0..number_of_users {
            users_arts.push(PrivateART::from_public_art(public_art.clone(), secrets[i]).unwrap());
        }

        for i in 0..number_of_users {
            // Assert creator and users computed the same tree key.
            assert_eq!(
                users_arts[i].recompute_root_key().unwrap().key,
                root_key.key
            );
        }

        let mut main_user_art = users_arts[main_user_id].clone();

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = get_random_scalar();
        let (new_key, changes) = main_user_art.update_key(&main_new_key).unwrap();

        assert_ne!(new_key.key, main_old_key);

        for i in 0..number_of_users {
            if i != main_user_id {
                users_arts[i].update_public_art(&changes).unwrap();
                assert_eq!(users_arts[i].recompute_root_key().unwrap().key, new_key.key);
            }
        }

        let (recomputed_old_key, changes) = main_user_art.update_key(&main_old_key).unwrap();

        assert_eq!(root_key.key, recomputed_old_key.key);

        for i in 0..number_of_users {
            if i != main_user_id {
                users_arts[i].update_public_art(&changes).unwrap();
                assert_eq!(
                    users_arts[i].recompute_root_key().unwrap().key,
                    recomputed_old_key.key
                );
            }
        }
    }

    #[test]
    fn test_art_weights_correctness() {
        let number_of_users = 10;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 0..number_of_users {
            let _ = tree.append_node(&Fr::rand(&mut rng)).unwrap();
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
        let number_of_users = 100;
        let secrets = create_random_secrets(number_of_users);

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
        let mut rng = rng();
        let number_of_users = 100;
        let secrets = create_random_secrets(number_of_users);

        let main_user_id = rng.random_range(0..(number_of_users - 2));
        let mut blank_user_id = rng.random_range(0..(number_of_users - 3));
        while blank_user_id >= main_user_id && blank_user_id <= main_user_id + 2 {
            blank_user_id = rng.random_range(0..(number_of_users - 3));
        }

        let mut rng = StdRng::seed_from_u64(rand::random());

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut users_arts = Vec::new();
        for i in 0..number_of_users {
            users_arts.push(PrivateART::from_public_art(public_art.clone(), secrets[i]).unwrap());
        }

        for i in 0..number_of_users {
            // Assert all the users computed the same tree key.
            assert_eq!(
                users_arts[i].recompute_root_key().unwrap().key,
                root_key.key
            );
        }

        let mut main_user_art = users_arts[main_user_id].clone();
        let temporary_public_key = CortadoAffine::generator()
            .mul(secrets[blank_user_id])
            .into_affine();
        let temporary_secret = Fr::rand(&mut rng);

        let (root_key, changes) = main_user_art
            .make_blank(&temporary_public_key, &temporary_secret)
            .unwrap();

        assert_eq!(
            main_user_art.recompute_root_key().unwrap().key,
            root_key.key
        );

        for i in 0..number_of_users {
            if i != blank_user_id && i != main_user_id {
                assert_ne!(
                    users_arts[i].recompute_root_key().unwrap().key,
                    root_key.key
                );

                users_arts[i].update_public_art(&changes).unwrap();
                let user_root_key = users_arts[i].recompute_root_key().unwrap();

                assert_eq!(user_root_key.key, root_key.key);
                assert_eq!(users_arts[i].get_root().weight, number_of_users - 1);
            }
        }

        let new_lambda = Fr::rand(&mut rng);

        let (root_key2, changes2) = main_user_art.append_node(&new_lambda).unwrap();

        assert_ne!(root_key2.key, root_key.key);

        for i in 0..number_of_users {
            if i != main_user_id && i != blank_user_id {
                users_arts[i].update_private_art(&changes2).unwrap();

                assert_eq!(
                    users_arts[i].recompute_root_key().unwrap().key,
                    root_key2.key
                );
                assert_eq!(users_arts[i].get_root().weight, number_of_users);
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
    fn art_balance() {
        for i in 1..100 {
            let secrets = create_random_secrets(i);
            let (art, _) =
                PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();
            assert!(get_disbalance(&art).unwrap() < 2);
        }
    }

    #[test]
    fn test_key_update_proof() {
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(100);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let mut test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[2])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (_, key_update_changes) = art.update_key(&new_secret_key).unwrap();
        let (_, artefacts) = art.recompute_root_key_with_artefacts().unwrap();

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
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(100);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let target_public_key = art.public_key_of(&secrets[1]);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (_, make_blank_changes) = art.make_blank(&target_public_key, &new_secret_key).unwrap();
        let (_, artefacts) = art
            .recompute_root_key_with_artefacts_using_secret_key(
                new_secret_key,
                Some(&make_blank_changes.node_index),
            )
            .unwrap();

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
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(100);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = Fr::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        let (_, append_node_changes) = art.append_node(&new_secret_key).unwrap();
        let (_, artefacts) = art
            .recompute_root_key_with_artefacts_using_secret_key(
                new_secret_key,
                Some(&append_node_changes.node_index),
            )
            .unwrap();

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
        let (_, make_blank_changes) = art.make_blank(&target_public_key, &new_secret_key).unwrap();
        test_art.update_public_art(&make_blank_changes).unwrap();

        let (_, append_node_changes) = art.append_node(&new_secret_key).unwrap();
        let (_, artefacts) = art
            .recompute_root_key_with_artefacts_using_secret_key(
                new_secret_key,
                Some(&append_node_changes.node_index),
            )
            .unwrap();

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

        let art_size = 7;

        let secrets = create_random_secrets(art_size);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..art_size {
            let art = PrivateART::<CortadoAffine>::try_from((&art, secrets[i]))
                .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut first = user_arts.remove(3);
        let mut second = user_arts.remove(4);

        let first_secret = create_random_secrets(1)[0];
        let second_secret = create_random_secrets(1)[0];
        let first_public_key = CortadoAffine::generator().mul(first_secret).into_affine();
        let second_public_key = CortadoAffine::generator().mul(second_secret).into_affine();

        let (_, first_changes) = first.update_key(&first_secret).unwrap();
        let (_, second_changes) = second.update_key(&second_secret).unwrap();

        let first_merged = vec![first_changes.clone()];
        let second_merged = vec![second_changes.clone()];

        let first_clone = first.clone();
        let second_clone = second.clone();
        first.merge_change(&first_merged, &second_changes).unwrap();
        second.merge_change(&second_merged, &first_changes).unwrap();

        assert_eq!(first.root.weight, second.root.weight);
        // info!("first:\n{}", first.root);
        // info!("second:\n{}", second.root);
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
        for i in 0..art_size - 2 {
            match rng.random_bool(0.5) {
                true => {
                    user_arts[i].update_public_art(&first_changes).unwrap();
                    user_arts[i]
                        .merge_change(&first_merged, &second_changes)
                        .unwrap();
                }
                false => {
                    user_arts[i].update_public_art(&second_changes).unwrap();
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

        let art_size = 7;

        let secrets = create_random_secrets(art_size);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..art_size {
            let art = PrivateART::<CortadoAffine>::try_from((&art, secrets[i]))
                .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut first = user_arts.remove(3);
        let mut second = user_arts.remove(4);

        let first_secret = create_random_secrets(1)[0];
        let second_secret = create_random_secrets(1)[0];
        let first_public_key = CortadoAffine::generator().mul(first_secret).into_affine();
        let second_public_key = CortadoAffine::generator().mul(second_secret).into_affine();

        let (_, first_changes) = first.update_key(&first_secret).unwrap();
        let (_, second_changes) = second.update_key(&second_secret).unwrap();

        let first_merged = vec![first_changes.clone()];
        let second_merged = vec![second_changes.clone()];

        let first_clone = first.clone();
        let second_clone = second.clone();
        first.merge_change(&first_merged, &second_changes).unwrap();
        second.merge_change(&second_merged, &first_changes).unwrap();

        assert_eq!(first.root.weight, second.root.weight);
        // info!("first:\n{}", first.root);
        // info!("second:\n{}", second.root);
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
        let mut rng = rand::rng();
        for i in 0..art_size - 2 {
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
        }
    }

    #[test]
    fn test_merge_for_add_member() {
        init_tracing_for_test();

        let art_size = 8;

        let secrets = create_random_secrets(art_size);
        let art = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        let mut user_arts = Vec::new();
        for i in 0..art_size {
            let art = PrivateART::<CortadoAffine>::try_from((&art, secrets[i]))
                .expect("Failed to deserialize art");
            user_arts.push(art);
        }

        let mut art1 = user_arts.remove(1);
        let mut art2 = user_arts.remove(2);
        let mut art3 = user_arts.remove(3);
        let mut art4 = user_arts.remove(4);

        let new_node1_sk = create_random_secrets(1)[0];
        let new_node2_sk = create_random_secrets(1)[0];
        let new_node3_sk = create_random_secrets(1)[0];
        let new_node4_sk = create_random_secrets(1)[0];

        let (_, changes1) = art1.update_key(&new_node1_sk).unwrap();
        let (_, changes2) = art2.update_key(&new_node2_sk).unwrap();
        let (_, changes3) = art3.append_node(&new_node3_sk).unwrap();
        let (_, changes4) = art4.append_node(&new_node4_sk).unwrap();

        // create two new users, from corresponding arts
        let mut new_user1 = PrivateART::try_from((&art1, new_node1_sk)).unwrap();

        art1.merge_with_skip(
            &vec![changes1.clone()],
            &vec![changes2.clone(), changes3.clone(), changes4.clone()],
        )
        .unwrap();
        art2.merge_with_skip(
            &vec![changes2.clone()],
            &vec![changes1.clone(), changes3.clone(), changes4.clone()],
        )
        .unwrap();
        new_user1
            .merge(&vec![
                changes1.clone(),
                changes2.clone(),
                changes3.clone(),
                changes4.clone(),
            ])
            .unwrap();

        assert_eq!(art1.root, art2.root);
        assert_eq!(art1.root.public_key, new_user1.root.public_key);
        assert_eq!(art1.root, art2.root);

        let all_changes = vec![changes1, changes2, changes3, changes4];

        user_arts[0].merge(&all_changes).unwrap();
        let first_root = user_arts[0].root.clone();

        let mut rng = rand::rng();
        for i in 1..art_size - 4 {
            match rng.random_bool(0.5) {
                true => {
                    user_arts[i].merge(&all_changes).unwrap();
                }
                false => {
                    user_arts[i].merge(&all_changes).unwrap();
                }
            }

            assert_eq!(user_arts[i].root, first_root);
        }
    }

    fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        (0..size).map(|_| F::rand(&mut rng)).collect()
    }

    fn min_max_leaf_height(art: &PrivateART<CortadoAffine>) -> Result<(u32, u32), ARTError> {
        let mut min_height = u32::MAX;
        let mut max_height = u32::MIN;
        let root = art.get_root();

        for (_, path) in LeafIterWithPath::new(root) {
            min_height = min(min_height, path.len() as u32);
            max_height = max(max_height, path.len() as u32);
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(art: &PrivateART<CortadoAffine>) -> Result<u32, ARTError> {
        let (min_height, max_height) = min_max_leaf_height(&art)?;

        Ok(max_height - min_height)
    }

    /// Returns random scalar, which is not one or zero.
    fn get_random_scalar() -> Fr {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let mut k = Fr::zero();
        while k.is_one() || k.is_zero() {
            k = Fr::rand(&mut rng);
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

    /// Try to init console logger with RUST_LOG level filter
    fn init_tracing_for_test() {
        _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_target(false)
            .try_init();
    }
}
