#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::Field;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use ark_std::{One, UniformRand, Zero};
    use art::{
        errors::ARTError,
        traits::{ARTPrivateAPI, ARTPublicAPI, ARTPublicView},
        types::{Direction, PrivateART, PublicART},
    };
    use cortado::{CortadoAffine as ARTGroup, Fr as ARTScalarField};
    use rand::{Rng, rng};
    use std::cmp::{max, min};
    use std::ops::Mul;

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
        let number_of_users = 100;
        let secrets = create_random_secrets(number_of_users);

        let (mut tree, _) =
            PrivateART::new_art_from_secrets(&secrets, &ARTGroup::generator()).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());
        for _ in 0..10 {
            let _ = tree.append_node(&ARTScalarField::rand(&mut rng)).unwrap();
        }

        let mut path = vec![tree.get_root().as_ref()];
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
                if last_node.is_blank {
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
        let main_user_id = rng.random_range(0..(number_of_users - 2));

        let secrets = create_random_secrets(number_of_users);

        let mut temporary_user_id = rng.random_range(0..(number_of_users - 3));
        while temporary_user_id >= main_user_id && temporary_user_id <= main_user_id + 2 {
            temporary_user_id = rng.random_range(0..(number_of_users - 3));
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
            .mul(secrets[temporary_user_id])
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
            if i != temporary_user_id && i != main_user_id {
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
            if i != main_user_id && i != temporary_user_id {
                users_arts[i].update_private_art(&changes2).unwrap();
                // users_arts[i].update_node_index().unwrap();

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
        let node_pk = tree.get_node_by_coordinate(0, 0).unwrap().get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(1, 0).unwrap().get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(1, 1).unwrap().get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_coordinate(4, 0).unwrap().get_public_key();
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

        let node_pk = tree.get_node_by_coordinate(4, 11).unwrap().get_public_key();
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

        let node_pk = tree.get_node_by_coordinate(4, 15).unwrap().get_public_key();
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

        let node_pk = tree.get_node_by_coordinate(5, 31).unwrap().get_public_key();
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
        let node_pk = tree.get_node_by_index(1).unwrap().get_public_key();
        let root_pk = tree.get_root().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_index(2).unwrap().get_public_key();
        let root_pk = tree.get_root().get_left().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_index(3).unwrap().get_public_key();
        let root_pk = tree.get_root().get_right().unwrap().get_public_key();
        assert!(root_pk.eq(&node_pk));

        let node_pk = tree.get_node_by_index(27).unwrap().get_public_key();
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
        let rec_node_pk = tree.get_node_by_index(node_index).unwrap().get_public_key();
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

    fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        (0..size).map(|_| F::rand(&mut rng)).collect()
    }

    // return random ScalarField element, which isn't zero or one
    fn random_non_neutral_scalar_field_element<F: Field>() -> F {
        let mut rng = StdRng::seed_from_u64(rand::random());

        let mut k = F::zero();
        while k.is_one() || k.is_zero() {
            k = F::rand(&mut rng);
        }

        k
    }

    fn min_max_leaf_height(art: &PrivateART<ARTGroup>) -> Result<(usize, usize), ARTError> {
        let mut min_height = usize::MAX;
        let mut max_height = 0;
        let root = art.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                min_height = min(min_height, path.len());
                max_height = max(max_height, path.len());

                path.pop();
                next.pop();
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right()?.as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left()?.as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(art: &PrivateART<ARTGroup>) -> Result<usize, ARTError> {
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
}
