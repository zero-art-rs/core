mod utils;

#[cfg(feature = "fuzz_test")]
#[cfg(test)]
mod tests {
    use super::utils::init_tracing_for_test;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::Rng;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::cmp::{max, min};
    use std::ops::Mul;
    use tracing::{debug, info, warn};
    use zrt_art::art::ArtAdvancedOps;
    use zrt_art::art::{PrivateArt, PublicArt};
    use zrt_art::art_node::{LeafIterWithPath, TreeMethods};
    use zrt_art::changes::ApplicableChange;
    use zrt_art::errors::ArtError;
    use zrt_art::node_index::NodeIndex;

    pub const SEED: u64 = 23;
    // pub const GROUP_INIT_SIZE: usize = 100;
    pub const GROUP_SIZE: usize = 100;
    pub const FUZ_LENGTH: usize = 500;

    trait TestART {
        fn min_max_leaf_height(&self) -> Result<(u64, u64), ArtError>;

        fn get_disbalance(&self) -> Result<u64, ArtError>;
    }

    impl TestART for PrivateArt<CortadoAffine> {
        fn min_max_leaf_height(&self) -> Result<(u64, u64), ArtError> {
            let mut min_height = u64::MAX;
            let mut max_height = u64::MIN;
            let root = self.root();

            for (_, path) in LeafIterWithPath::new(root) {
                min_height = min(min_height, path.len() as u64);
                max_height = max(max_height, path.len() as u64);
            }

            Ok((min_height, max_height))
        }

        fn get_disbalance(&self) -> Result<u64, ArtError> {
            let (min_height, max_height) = self.min_max_leaf_height()?;

            Ok(max_height - min_height)
        }
    }

    #[test]
    fn fuzz_test() {
        init_tracing_for_test();

        info!(
            "Init test context for group of size {}, with seed: {}.",
            GROUP_SIZE, SEED,
        );
        // let mut seeded_rng = StdRng::seed_from_u64(seed);
        let mut rng = StdRng::seed_from_u64(SEED);
        let group_secrets = std::iter::repeat_with(|| Fr::rand(&mut rng))
            .take(GROUP_SIZE)
            .collect::<Vec<Fr>>();

        let user0 = PrivateArt::<CortadoAffine>::setup(&group_secrets).unwrap();

        // Serialise and deserialize art for all the users (including the creator).
        let mut group_arts = Vec::with_capacity(GROUP_SIZE);

        for sk in &group_secrets {
            group_arts
                .push(PrivateArt::<CortadoAffine>::new(user0.public_art().clone(), *sk).unwrap())
        }

        // Assert all the arts are correctly computed
        for art in &group_arts {
            assert!(
                user0.eq(art),
                "Deserialized art is the same as the source one."
            );
            assert_eq!(
                art.node_index().get_path().unwrap().len() + 1,
                art.secrets().secrets().len(),
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
        group_arts: &mut Vec<PrivateArt<CortadoAffine>>,
        target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: key update for user {:?}.",
            group_arts[target_user].node_index()
        );

        let new_sk = Fr::rand(&mut *rng);
        let (_, change) = group_arts[target_user].update_key(new_sk).unwrap();
        group_arts[target_user].apply(&new_sk).unwrap();
        group_arts[target_user].commit().unwrap();

        assert_eq!(
            group_arts[target_user]
                .root()
                .node(&change.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator().mul(new_sk).into_affine(),
            "Key updated correctly"
        );

        for i in 0..group_arts.len() {
            let old_sk = group_arts[i].secrets().leaf();

            if i != target_user {
                group_arts[i].apply(&change).unwrap();
                group_arts[i].commit().unwrap();
            }

            if i != target_user {
                assert_eq!(
                    old_sk,
                    group_arts[i].leaf_secret_key(),
                    "Sanity check: User secret key didn't changed."
                );
            }
            assert_eq!(
                group_arts[i].node_index().get_path().unwrap().len() + 1,
                group_arts[i].secrets().secrets().len(),
            );
            assert_eq!(
                group_arts[target_user], group_arts[i],
                "Both users have the same view on the state of the art."
            );
        }
    }

    fn fuz_test_add_member(
        group_arts: &mut Vec<PrivateArt<CortadoAffine>>,
        target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: add member using user {:?}.",
            group_arts[target_user].node_index()
        );

        let new_sk = Fr::rand(&mut *rng);
        let (_, change) = group_arts[target_user].add_member(new_sk).unwrap();
        group_arts[target_user].apply(&change).unwrap();
        group_arts[target_user].commit().unwrap();

        let index_len = change.node_index.get_path().unwrap().len();
        if index_len + 1 == change.public_keys.len() {
            assert_eq!(
                group_arts[target_user]
                    .root()
                    .node(&change.node_index)
                    .unwrap()
                    .public_key(),
                CortadoAffine::generator().mul(new_sk).into_affine(),
                "Key updated correctly."
            );
        } else if index_len + 2 == change.public_keys.len() {
            assert_eq!(
                group_arts[target_user]
                    .root()
                    .node(&change.node_index)
                    .unwrap()
                    .right()
                    .unwrap()
                    .public_key(),
                CortadoAffine::generator().mul(new_sk).into_affine(),
                "Key updated correctly."
            );
        } else {
            panic!("Invalid key update change.")
        }

        // Serialise and deserialize art for the new user.
        let public_art_bytes = to_allocvec(&group_arts[target_user].public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();
        let new_user: PrivateArt<CortadoAffine> = PrivateArt::new(public_art, new_sk).unwrap();

        // Sync arts for other users other users
        for i in 0..group_arts.len() {
            let old_sk = group_arts[i].leaf_secret_key();

            if i != target_user {
                change.apply(&mut group_arts[i]).unwrap();
                group_arts[i].commit().unwrap();
            }

            assert_eq!(
                old_sk,
                group_arts[i].leaf_secret_key(),
                "Sanity check: secret key didn't changed for user {:?}.",
                group_arts[i].node_index(),
            );
            assert_eq!(
                group_arts[i].node_index().get_path().unwrap().len() + 1,
                group_arts[i].secrets().secrets().len(),
                "Length of `path_secrets` = direction_path + 1 for user {}: {:?}.",
                i,
                group_arts[i].node_index(),
            );
            assert_eq!(
                group_arts[target_user].root_secret_key(),
                group_arts[i].root_secret_key(),
                "Both users have the same view on the state of the art.",
            );
            assert_eq!(
                group_arts[target_user], group_arts[i],
                "Both users have the same view on the state of the art.",
            );
            assert!(
                group_arts[i].get_disbalance().unwrap() < 2,
                "Sanity check: art disbalance {} stays low. in art\n{}",
                group_arts[i].get_disbalance().unwrap(),
                group_arts[i].root(),
            );
        }

        group_arts.push(new_user);
    }

    /// Test blanking user once.
    fn fuz_test_make_blank(
        group_arts: &mut Vec<PrivateArt<CortadoAffine>>,
        target_user: usize,
        blank_target_user: usize,
        rng: &mut StdRng,
    ) {
        info!(
            "Fuz test: make user {:?} blank, using user {:?}.",
            group_arts[blank_target_user].node_index(),
            group_arts[target_user].node_index(),
        );

        let blank_target_node_path = group_arts[blank_target_user]
            .node_index()
            .get_path()
            .unwrap();
        let blank_target_node_index = NodeIndex::from(blank_target_node_path.to_vec());
        let new_sk = Fr::rand(&mut *rng);
        let (_, change) = group_arts[target_user]
            .remove_member(&blank_target_node_index, new_sk)
            .unwrap();
        group_arts[target_user].apply(&change).unwrap();
        group_arts[target_user].commit().unwrap();

        assert_eq!(
            group_arts[target_user]
                .root()
                .node(&change.node_index)
                .unwrap()
                .public_key(),
            CortadoAffine::generator().mul(new_sk).into_affine(),
            "Key updated correctly"
        );

        // Sync arts for other users other users
        for i in 0..group_arts.len() {
            let old_sk = group_arts[i].leaf_secret_key();

            // bug fix for blank member
            if i == blank_target_user {
                continue;
            }

            if i != target_user && i != blank_target_user {
                change.apply(&mut group_arts[i]).unwrap();
                group_arts[i].commit().unwrap();
            }

            assert_eq!(
                old_sk,
                group_arts[i].leaf_secret_key(),
                "Sanity check: secret key didn't changed for user {:?}.",
                group_arts[i].node_index(),
            );
            assert_eq!(
                group_arts[i].node_index().get_path().unwrap().len() + 1,
                group_arts[i].secrets().secrets().len(),
                "Length of path secrets is length of direction path to node + 1 for user_{i}: {:?}.",
                group_arts[i].node_index(),
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
