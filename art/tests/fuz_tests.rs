mod utils;

#[cfg(feature = "fuzz_test")]
#[cfg(test)]
mod tests {
    use super::utils::init_tracing_for_test;
    use ark_ec::AffineRepr;
    use ark_std::UniformRand;
    use ark_std::rand::Rng;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use std::cmp::{max, min};
    use tracing::{debug, info, warn};
    use zrt_art::art::{LeafIterWithPath, PrivateART};
    use zrt_art::errors::ARTError;

    pub const SEED: u64 = 23;
    pub const GROUP_SIZE: usize = 10;
    pub const FUZ_LENGTH: usize = 500;

    trait TestART {
        fn min_max_leaf_height(&self) -> Result<(u64, u64), ARTError>;

        fn get_disbalance(&self) -> Result<u64, ARTError>;
    }

    impl TestART for PrivateART<CortadoAffine> {
        fn min_max_leaf_height(&self) -> Result<(u64, u64), ARTError> {
            let mut min_height = u64::MAX;
            let mut max_height = u64::MIN;
            let root = self.get_root();

            for (_, path) in LeafIterWithPath::new(root) {
                min_height = min(min_height, path.len() as u64);
                max_height = max(max_height, path.len() as u64);
            }

            Ok((min_height, max_height))
        }

        fn get_disbalance(&self) -> Result<u64, ARTError> {
            let (min_height, max_height) = self.min_max_leaf_height()?;

            Ok(max_height - min_height)
        }
    }

    #[test]
    fn fuzz_test() {
        init_tracing_for_test();

        info!(
            "Init test context for group of size {}, with seed: {}.",
            FUZ_LENGTH, SEED
        );
        // let mut seeded_rng = StdRng::seed_from_u64(seed);
        let mut rng = StdRng::seed_from_u64(SEED);
        let group_secrets = std::iter::repeat_with(|| Fr::rand(&mut rng))
            .take(GROUP_SIZE)
            .collect::<Vec<Fr>>();

        let (user0, _) = PrivateART::<CortadoAffine>::new_art_from_secrets(
            &group_secrets,
            &CortadoAffine::generator(),
        )
        .unwrap();

        // Serialise and deserialize art for all the users (including the creator).
        let mut group_arts = Vec::with_capacity(GROUP_SIZE);
        let public_art_bytes = user0.serialize().unwrap();
        for sk in &group_secrets {
            group_arts
                .push(PrivateART::<CortadoAffine>::deserialize(&public_art_bytes, sk).unwrap())
        }

        // Assert all the arts are correctly computed
        for art in &group_arts {
            assert!(
                user0.eq(art),
                "Deserialized art is the same as the source one."
            );
            assert_eq!(
                art.get_node_index().get_path().unwrap().len() + 1,
                art.get_path_secrets().len(),
            );
        }

        info!("Perform {FUZ_LENGTH} updates ...");
        for i in 0..FUZ_LENGTH {
            let target_user = rng.gen_range(0..group_arts.len());
            match rng.gen_range(0..3) {
                0 => fuz_test_key_update(&mut group_arts, target_user, &mut rng),
                1 => fuz_test_add_member(&mut group_arts, target_user, &mut rng),
                2 => {
                    let mut blank_target_user = rng.gen_range(0..group_arts.len());
                    while blank_target_user == target_user {
                        blank_target_user = rng.gen_range(0..group_arts.len());
                    }

                    fuz_test_make_blank(&mut group_arts, target_user, blank_target_user, &mut rng)
                }
                _ => warn!("Overhead"),
            }
        }
    }

    fn fuz_test_key_update(
        group_arts: &mut Vec<PrivateART<CortadoAffine>>,
        target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: key update for user {:?}.",
            group_arts[target_user].get_node_index()
        );

        let new_sk = Fr::rand(&mut *rng);
        let (new_tk, change, artefacts) = group_arts[target_user].update_key(&new_sk).unwrap();

        assert_eq!(
            group_arts[target_user]
                .get_public_art()
                .get_node(&change.node_index)
                .unwrap()
                .get_public_key(),
            group_arts[target_user].public_key_of(&new_sk),
            "Key updated correctly"
        );
        assert_eq!(
            new_tk,
            group_arts[target_user].get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        for i in 0..group_arts.len() {
            let path_secrets_len_before = group_arts[i].get_path_secrets().len();
            let old_sk = group_arts[i].get_path_secrets()[0];

            if i != target_user {
                group_arts[i].update(&change).unwrap()
            }

            assert_eq!(
                old_sk,
                group_arts[i].get_path_secrets()[0],
                "Sanity check: User secret key didn't changed."
            );
            assert_eq!(
                group_arts[i].get_node_index().get_path().unwrap().len() + 1,
                group_arts[i].get_path_secrets().len(),
            );
            assert_eq!(
                group_arts[target_user], group_arts[i],
                "Both users have the same view on the state of the art."
            );
        }
    }

    fn fuz_test_add_member(
        group_arts: &mut Vec<PrivateART<CortadoAffine>>,
        target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: add member using user {:?}.",
            group_arts[target_user].get_node_index()
        );

        let new_sk = Fr::rand(&mut *rng);
        let (new_tk, change, artefacts) = group_arts[target_user]
            .append_or_replace_node(&new_sk)
            .unwrap();

        assert_eq!(
            group_arts[target_user]
                .get_public_art()
                .get_node(&change.node_index)
                .unwrap()
                .get_public_key(),
            group_arts[target_user].public_key_of(&new_sk),
            "Key updated correctly."
        );
        assert_eq!(
            new_tk,
            group_arts[target_user].get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Serialise and deserialize art for the new user.
        let public_art_bytes = group_arts[target_user].serialize().unwrap();
        let new_user: PrivateART<CortadoAffine> =
            PrivateART::deserialize(&public_art_bytes, &new_sk).unwrap();

        info!("    New user node: {:?}.", new_user.get_node_index());

        // Sync arts for other users other users
        for i in 0..group_arts.len() {
            let old_sk = group_arts[i].get_path_secrets()[0];

            if i != target_user {
                group_arts[i].update(&change).unwrap()
            }

            assert_eq!(
                old_sk,
                group_arts[i].get_path_secrets()[0],
                "Sanity check: secret key didn't changed for user {:?}.",
                group_arts[i].get_node_index(),
            );
            assert_eq!(
                group_arts[i].get_node_index().get_path().unwrap().len() + 1,
                group_arts[i].get_path_secrets().len(),
                "Length of `path_secrets` = direction_path + 1 for user {}: {:?}.",
                i,
                group_arts[i].get_node_index(),
            );
            assert_eq!(
                group_arts[target_user].get_root_key().unwrap(),
                group_arts[i].get_root_key().unwrap(),
                "Both users have the same view on the state of the art.",
            );
            assert_eq!(
                group_arts[i].get_secret_key(),
                group_arts[i].get_path_secrets()[0],
                "Users path_secrets contain his secret key.",
            );
            assert_eq!(
                group_arts[target_user], group_arts[i],
                "Both users have the same view on the state of the art.",
            );
            assert!(
                group_arts[i].get_disbalance().unwrap() < 2,
                "Sanity check: art disbalance {} stays low. in art\n{}",
                group_arts[i].get_disbalance().unwrap(),
                group_arts[i].get_root(),
            );
        }

        group_arts.push(new_user);
    }

    /// Test blanking user once.
    fn fuz_test_make_blank(
        group_arts: &mut Vec<PrivateART<CortadoAffine>>,
        target_user: usize,
        blank_target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: make user {:?} blank, using user {:?}.",
            group_arts[blank_target_user].get_node_index(),
            group_arts[target_user].get_node_index(),
        );

        let blank_target_node_index = group_arts[blank_target_user]
            .get_node_index()
            .get_path()
            .unwrap();
        let new_sk = Fr::rand(&mut *rng);
        let (new_tk, change, artefacts) = group_arts[target_user]
            .make_blank(&blank_target_node_index, &new_sk)
            .unwrap();

        assert_eq!(
            group_arts[target_user]
                .get_public_art()
                .get_node(&change.node_index)
                .unwrap()
                .get_public_key(),
            group_arts[target_user].public_key_of(&new_sk),
            "Key updated correctly"
        );
        assert_eq!(
            new_tk,
            group_arts[target_user].get_root_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Sync arts for other users other users
        for i in 0..group_arts.len() {
            let old_sk = group_arts[i].get_path_secrets()[0];

            // bug fix for blank member
            if i == blank_target_user {
                continue;
            }

            if i != target_user && i != blank_target_user {
                group_arts[i].update(&change).unwrap()
            }

            assert_eq!(
                old_sk,
                group_arts[i].get_path_secrets()[0],
                "Sanity check: secret key didn't changed for user {:?}.",
                group_arts[i].get_node_index(),
            );
            assert_eq!(
                group_arts[i].get_node_index().get_path().unwrap().len() + 1,
                group_arts[i].get_path_secrets().len(),
                "Length of path secrets is length of direction path to node + 1 for user_{i}: {:?}.",
                group_arts[i].get_node_index(),
            );
            assert_eq!(
                group_arts[target_user], group_arts[i],
                "Both users have the same view on the state of the art."
            );
            assert!(
                group_arts[i].get_disbalance().unwrap() < 2,
                "Sanity check: disbalance stays low."
            );
        }

        group_arts.remove(blank_target_user);
    }
}
