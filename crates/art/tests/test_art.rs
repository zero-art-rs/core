#[cfg(test)]
mod tests {
    use ark_bn254::{G1Affine as ARTGroup, fr::Fr as ARTScalarField};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::Field;
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use art::{ART, Direction};
    use rand::{Rng, rng};
    use std::ops::Mul;

    pub fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        (0..size).map(|_| F::rand(&mut rng)).collect()
    }

    // return random ScalarField element, which isn't zero or one
    pub fn random_non_neutral_scalar_field_element<F: Field>() -> F {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let mut k = F::zero();
        while k.is_one() || k.is_zero() {
            k = F::rand(&mut rng);
        }

        k
    }

    #[test]
    fn test_art_key_update() {
        let number_of_users = 100;
        let main_user_id = rng().random_range(0..number_of_users);
        let secrets = create_random_secrets(number_of_users);

        let (tree, root_key) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());

        let mut users_arts = Vec::new();
        for _ in 0..number_of_users {
            users_arts.push(tree.clone());
        }

        for i in 0..number_of_users {
            // Assert creator and users computed the same tree key.
            assert_eq!(
                users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
                root_key.key
            );
        }

        let mut main_user_art = users_arts[main_user_id].clone();

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = main_user_art.get_random_scalar();
        let (new_key, changes) = main_user_art
            .update_key(&secrets[main_user_id], &main_new_key)
            .unwrap();

        assert_ne!(new_key.key, main_old_key);

        for i in 0..number_of_users {
            if i != main_user_id {
                users_arts[i].update_art(&changes).unwrap();
                assert_eq!(
                    users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
                    new_key.key
                );
            }
        }

        let (recomputed_old_key, changes) = main_user_art
            .update_key(&main_new_key, &main_old_key)
            .unwrap();

        assert_eq!(root_key.key, recomputed_old_key.key);

        for i in 0..number_of_users {
            if i != main_user_id {
                users_arts[i].update_art(&changes).unwrap();
                assert_eq!(
                    users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
                    recomputed_old_key.key
                );
            }
        }
    }

    #[test]
    fn test_art_weights_correctness() {
        let number_of_users = 100;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());
        let mut rng = &mut StdRng::seed_from_u64(rand::random());
        for _ in 0..10 {
            let _ = tree.append_node(&ARTScalarField::rand(&mut rng)).unwrap();
        }

        let mut path = vec![tree.root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        // Use depth-first search to travers through all the nodes
        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if !last_node.is_leaf() {
                assert_eq!(
                    last_node.weight,
                    last_node.get_left().unwrap().weight + last_node.get_right().unwrap().weight
                );
            } else {
                if last_node.is_temporal {
                    assert_eq!(last_node.weight, 0);
                } else {
                    assert_eq!(last_node.weight, 1);
                }
            }

            if last_node.is_leaf() {
                path.pop();
                next.pop();
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right().unwrap().as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left().unwrap().as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }
    }

    #[test]
    fn test_art_tree_serialisation() {
        let number_of_users = 100;
        let secrets = create_random_secrets(number_of_users);

        let (tree, _) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());

        let serialized = tree.to_string().unwrap();
        let deserialized: ART<ARTGroup> = ART::from_string(&serialized).unwrap();

        assert!(deserialized.eq(&tree));
    }

    #[test]
    fn test_art_make_temporal_node() {
        let mut rng = rng();
        let number_of_users = 100;
        let main_user_id = rng.random_range(0..(number_of_users - 2));

        let secrets = create_random_secrets(number_of_users);

        let mut temporal_user_id = rng.random_range(0..(number_of_users - 3));
        while temporal_user_id >= main_user_id && temporal_user_id <= main_user_id + 2 {
            temporal_user_id = rng.random_range(0..(number_of_users - 3));
        }
        let mut rng = StdRng::seed_from_u64(rand::random());

        let (tree, root_key) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());

        let mut users_arts = Vec::new();
        for _ in 0..number_of_users {
            users_arts.push(tree.clone());
        }

        for i in 0..number_of_users {
            // Assert all the users computed the same tree key.
            assert_eq!(
                users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
                root_key.key
            );
        }

        let mut main_user_art = users_arts[main_user_id].clone();
        let temporal_public_key = ARTGroup::generator()
            .mul(secrets[temporal_user_id])
            .into_affine();
        let temporal_secret = ARTScalarField::rand(&mut rng);

        let (root_key, changes) = main_user_art
            .make_node_temporal(&temporal_public_key, &temporal_secret)
            .unwrap();

        assert_eq!(
            main_user_art
                .recompute_root_key(secrets[main_user_id])
                .unwrap()
                .key,
            root_key.key
        );

        for i in 0..number_of_users {
            if i != temporal_user_id && i != main_user_id {
                assert_ne!(
                    users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
                    root_key.key
                );

                users_arts[i].update_art(&changes).unwrap();
                let user_root_key = users_arts[i].recompute_root_key(secrets[i]).unwrap();

                assert_eq!(user_root_key.key, root_key.key);
                assert_eq!(users_arts[i].get_root().weight, (number_of_users - 1));
            }
        }

        let new_lambda = ARTScalarField::rand(&mut rng);

        let (root_key2, changes2) = main_user_art.append_node(&new_lambda).unwrap();

        assert_ne!(root_key2.key, root_key.key);

        for i in 0..number_of_users {
            if i != main_user_id && i != temporal_user_id {
                users_arts[i].update_art(&changes2).unwrap();

                assert_eq!(
                    users_arts[i].recompute_root_key(secrets[i]).unwrap().key,
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

        let (mut tree, _) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());
        let node_pk = tree.get_node_by_coordinate(0, 0).unwrap().get_public_key();
        let root_pk = tree.root.get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(1, 0).unwrap().get_public_key();
        let root_pk = tree.root.get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(1, 1).unwrap().get_public_key();
        let root_pk = tree.root.get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(4, 0).unwrap().get_public_key();
        let root_pk = tree
            .root
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

        let node_pk = tree.get_node_by_coordinate(4, 11).unwrap().get_public_key();
        let root_pk = tree
            .root
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

        let node_pk = tree.get_node_by_coordinate(4, 15).unwrap().get_public_key();
        let root_pk = tree
            .root
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

        let node_pk = tree.get_node_by_coordinate(5, 31).unwrap().get_public_key();
        let root_pk = tree
            .root
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

        let (mut tree, _) = ART::new_art_from_secrets(&secrets, &ARTGroup::generator());
        let node_pk = tree.get_node_index(0).unwrap().get_public_key();
        let root_pk = tree.root.get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_index(1).unwrap().get_public_key();
        let root_pk = tree.root.get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_index(2).unwrap().get_public_key();
        let root_pk = tree.root.get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_index(26).unwrap().get_public_key();
        let root_pk = tree
            .root
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
    }
}
