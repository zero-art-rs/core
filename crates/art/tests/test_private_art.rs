#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ed25519::EdwardsAffine as Ed25519Affine;
    use ark_ff::Field;
    use ark_serialize::CanonicalSerialize;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use ark_std::{One, UniformRand, Zero};
    use art::traits::ARTPrivateView;
    use art::types::{
        BranchChanges, LeafIterWithPath, NodeIndex, NodeIter, ProverArtefacts, VerifierArtefacts,
    };
    use art::{
        errors::ARTError,
        traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
        types::{PrivateART, PublicART},
    };
    use bulletproofs::PedersenGens;
    use bulletproofs::r1cs::R1CSError;
    use cortado::{CortadoAffine as ARTGroup, CortadoAffine, Fr as ARTScalarField};
    use curve25519_dalek::Scalar;
    use rand::{Rng, rng};
    use std::cmp::{max, min};
    use std::ops::Mul;
    use zk::art::{art_prove, art_verify};
    use zkp::toolbox::cross_dleq::PedersenBasis;
    use zkp::toolbox::dalek_ark::ristretto255_to_ark;

    #[test]
    fn test_art_key_update() {
        let number_of_users = 100;
        let main_user_id = rng().random_range(0..number_of_users);
        let secrets = create_random_secrets(number_of_users);

        let (public_art, root_key) =
            PublicART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 0..number_of_users {
            let _ = tree.append_node(&ARTScalarField::rand(&mut rng)).unwrap();
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

        let (tree, _) = PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

        let serialized = tree.serialize().unwrap();
        let deserialized: PrivateART<ARTGroup> =
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
            PublicART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

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
        let temporary_public_key = ARTGroup::generator()
            .mul(secrets[blank_user_id])
            .into_affine();
        let temporary_secret = ARTScalarField::rand(&mut rng);

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

        let new_lambda = ARTScalarField::rand(&mut rng);

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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();
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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();
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

        let node_pk = ARTGroup::generator().mul(&secrets[2]).into_affine();
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
                PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();
            assert!(get_disbalance(&art).unwrap() < 2);
        }
    }

    #[test]
    fn test_key_update_proof() {
        let mut rng = StdRng::seed_from_u64(rand::random());
        let secrets = create_random_secrets(100);
        let (mut art, _) =
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

        let mut test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[2])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = ARTScalarField::rand(&mut rng);

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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let target_public_key = art.public_key_of(&secrets[1]);
        let new_secret_key = ARTScalarField::rand(&mut rng);

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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

        let test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = ARTScalarField::rand(&mut rng);

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
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();

        let mut test_art = PrivateART::deserialize(&art.serialize().unwrap(), &secrets[4])
            .expect("Failed to deserialize art");

        let secret_key = art.secret_key.clone();
        let public_key = art.public_key_of(&secret_key);
        let new_secret_key = ARTScalarField::rand(&mut rng);

        let mut associated_data = Vec::new();
        art.root
            .public_key
            .serialize_uncompressed(&mut associated_data)
            .unwrap();

        // Make blank the node with index 1
        let target_public_key = art.public_key_of(&secrets[1]);
        let (_, make_blank_changes) = art.make_blank(&target_public_key, &new_secret_key).unwrap();
        test_art
            .update_art_with_changes(&make_blank_changes)
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

    fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        (0..size).map(|_| F::rand(&mut rng)).collect()
    }

    fn min_max_leaf_height(art: &PrivateART<ARTGroup>) -> Result<(u32, u32), ARTError> {
        let mut min_height = u32::MAX;
        let mut max_height = u32::MIN;
        let root = art.get_root();

        for (_, path) in LeafIterWithPath::new(root) {
            min_height = min(min_height, path.len() as u32);
            max_height = max(max_height, path.len() as u32);
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(art: &PrivateART<ARTGroup>) -> Result<u32, ARTError> {
        let (min_height, max_height) = min_max_leaf_height(&art)?;

        Ok(max_height - min_height)
    }

    /// Returns random scalar, which is not one or zero.
    fn get_random_scalar() -> ARTScalarField {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let mut k = ARTScalarField::zero();
        while k.is_one() || k.is_zero() {
            k = ARTScalarField::rand(&mut rng);
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
        aux_sk: Vec<ARTScalarField>,
        aux_pk: Vec<ARTGroup>,
        artefacts: ProverArtefacts<ARTGroup>,
        update_changes: BranchChanges<ARTGroup>,
        verification_artefacts: VerifierArtefacts<ARTGroup>,
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
