use crate::art::PrivateZeroArt;
use crate::art::art_types::PrivateArt;
use crate::changes::aggregations::{AggregatedChange, ChangeAggregation, ProverAggregationData};
use crate::errors::ArtError;
use crate::helper_tools::default_prover_engine;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use std::rc::Rc;
use zrt_zk::EligibilityArtefact;
use zrt_zk::aggregated_art::ProverAggregationTree;
use zrt_zk::engine::ZeroArtProverEngine;

pub struct AggregationContext<T, G, R>
where
    G: AffineRepr,
    R: Rng + ?Sized,
{
    pub(crate) prover_aggregation: ChangeAggregation<ProverAggregationData<G>>,
    pub(crate) operation_tree: T,
    pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
    pub(crate) rng: Box<R>,
    pub(crate) eligibility: EligibilityArtefact,
}

impl<T, G, R> AggregationContext<T, G, R>
where
    G: AffineRepr,
    R: Rng + ?Sized,
{
    pub fn get_operation_tree(&self) -> &T {
        &self.operation_tree
    }
}

impl<R> AggregationContext<PrivateArt<CortadoAffine>, CortadoAffine, R>
where
    R: Rng + ?Sized,
{
    pub fn new(operation_tree: PrivateArt<CortadoAffine>, rng: Box<R>) -> Self {
        let eligibility = EligibilityArtefact::Owner((
            operation_tree.get_leaf_secret_key(),
            operation_tree.get_leaf_public_key(),
        ));

        Self {
            prover_aggregation: Default::default(),
            operation_tree,
            prover_engine: Rc::new(default_prover_engine()),
            rng,
            eligibility,
        }
    }

    pub fn from_private_zero_art<RT>(
        operation_tree: &PrivateZeroArt<CortadoAffine, RT>,
        rng: Box<R>,
    ) -> Self
    where
        RT: Rng + ?Sized,
    {
        let eligibility = EligibilityArtefact::Owner((
            operation_tree.get_base_art().get_leaf_secret_key(),
            operation_tree.get_base_art().get_leaf_public_key(),
        ));

        Self {
            prover_aggregation: Default::default(),
            operation_tree: operation_tree.get_base_art().clone(),
            prover_engine: Rc::clone(&operation_tree.prover_engine),
            rng,
            eligibility,
        }
    }
}

impl<'a, T, R> TryFrom<&'a AggregationContext<T, CortadoAffine, R>>
    for ProverAggregationTree<CortadoAffine>
where
    R: Rng + ?Sized,
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<T, CortadoAffine, R>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

impl<'a, T, R> TryFrom<&'a AggregationContext<T, CortadoAffine, R>>
    for AggregatedChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<T, CortadoAffine, R>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

#[cfg(test)]
mod tests {
    use crate::TreeMethods;
    use crate::art::art_node::LeafIterWithPath;
    use crate::art::art_types::PrivateArt;
    use crate::art::{AggregationContext, ArtAdvancedOps, PrivateZeroArt};
    use crate::changes::ApplicableChange;
    use crate::changes::aggregations::{
        AggregatedChange, AggregationData, AggregationNodeIterWithPath, ChangeAggregation,
        VerifierAggregationData,
    };
    use crate::errors::ArtError;
    use crate::helper_tools::iota_function;
    use crate::node_index::NodeIndex;
    use crate::test_helper_tools::init_tracing;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use cortado::{CortadoAffine, Fr};
    use std::ops::Mul;
    use tracing::debug;
    use zrt_zk::aggregated_art::ProverAggregationTree;

    /// Test if non-mergable changes (without blank for the second time) can be aggregated and
    /// applied correctly.
    #[test]
    fn test_branch_aggregation() {
        init_tracing();

        // Init test context.
        let mut rng: StdRng = StdRng::seed_from_u64(0);
        let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

        // Serialise and deserialize art for the other users.
        let mut user1 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[2]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let mut user2 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[3]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let user1_2rng = Box::new(thread_rng());
        let user1_2 = user1.clone_without_rng(user1_2rng);

        let mut user3 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[4]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();
        let mut user4 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[5]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        // Create aggregation
        let mut agg = AggregationContext::new(user1.get_base_art().clone(), Box::new(thread_rng()));

        let sk1 = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let sk3 = Fr::rand(&mut rng);
        let sk4 = Fr::rand(&mut rng);

        agg.remove_member(&user3.get_node_index(), sk1).unwrap();

        agg.remove_member(&user4.get_node_index(), sk1).unwrap();

        agg.add_member(sk2).unwrap();

        agg.add_member(sk3).unwrap();

        agg.add_member(sk4).unwrap();

        // Check successful ProverAggregationTree conversion to tree_ds tree
        let tree_ds_tree = ProverAggregationTree::<CortadoAffine>::try_from(&agg);
        assert!(tree_ds_tree.is_ok());

        for _ in 0..100 {
            let sk_i = Fr::rand(&mut rng);
            agg.add_member(sk_i).unwrap();

            let aggregation = AggregatedChange::try_from(&agg).unwrap();

            let mut user2_clone_rng = Box::new(thread_rng());
            let mut user2_clone = user2.clone_without_rng(user2_clone_rng);
            aggregation.apply(&mut user2_clone).unwrap();

            assert_eq!(
                agg.operation_tree,
                user2_clone.upstream_art,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.upstream_art.get_root(),
            );
        }

        let root_clone = user1.upstream_art.get_root().clone();
        let leaf_iter = LeafIterWithPath::new(&root_clone).skip(10).take(10);
        for (_, path) in leaf_iter {
            let path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            agg.remove_member(&NodeIndex::Direction(path), Fr::rand(&mut rng))
                .unwrap();

            let aggregation = AggregatedChange::try_from(&agg).unwrap();
            let verifier_aggregation = aggregation
                .add_co_path(user2.base_art.get_public_art())
                .unwrap();

            let user2_clone_rng = Box::new(thread_rng());
            let mut user2_clone = user2.clone_without_rng(user2_clone_rng);
            aggregation.apply(&mut user2_clone).unwrap();

            assert_eq!(
                agg.operation_tree,
                user2_clone.upstream_art,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.upstream_art.get_root(),
            );
        }

        for i in 0..100 {
            let sk_i = Fr::rand(&mut rng);
            agg.add_member(sk_i).unwrap();

            let aggregation = AggregatedChange::try_from(&agg).unwrap();

            let user2_clone_rng = Box::new(thread_rng());
            let mut user2_clone = user2.clone_without_rng(user2_clone_rng);
            aggregation.apply(&mut user2_clone).unwrap();

            assert_eq!(
                agg.operation_tree,
                user2_clone.upstream_art,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.upstream_art.get_root(),
            );
        }

        // Verify structure correctness
        for (node, path) in AggregationNodeIterWithPath::from(&agg.prover_aggregation) {
            assert_eq!(
                CortadoAffine::generator()
                    .mul(node.data.secret_key)
                    .into_affine(),
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
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(
                &agg.prover_aggregation,
            )
            .unwrap();

        let aggregation_from_prover =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        let aggregation_from_verifier =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&verifier_aggregation)
                .unwrap();

        assert_eq!(
            aggregation_from_prover, aggregation_from_verifier,
            "Aggregations are equal from both sources."
        );

        let extracted_verifier_aggregation = aggregation_from_prover
            .add_co_path(user2.base_art.get_public_art())
            .unwrap();

        assert_eq!(
            verifier_aggregation, extracted_verifier_aggregation,
            "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
            verifier_aggregation, extracted_verifier_aggregation,
        );

        let mut user1_2_rng = Box::new(thread_rng());
        let mut user1_clone = user1_2.clone_without_rng(user1_2_rng);
        agg.apply(&mut user1_clone).unwrap();
        agg.apply(&mut user2).unwrap();

        assert_eq!(
            agg.operation_tree,
            user1_clone.upstream_art,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_clone\n{}",
            agg.operation_tree.get_root(),
            user1_clone.upstream_art.get_root(),
        );

        assert_eq!(
            agg.operation_tree,
            user2.upstream_art,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser2\n{}",
            agg.operation_tree.get_root(),
            user2.upstream_art.get_root(),
        );
    }

    #[test]
    fn test_branch_aggregation_with_blanking() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = (0..group_length)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let base_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(base_art, user0_rng).unwrap();

        let user3_path = NodeIndex::from(
            user0
                .get_base_art()
                .get_public_art()
                .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[4]).into_affine())
                .unwrap(),
        );
        let change = user0
            .remove_member(&user3_path, Fr::rand(&mut rng))
            .unwrap();
        debug!("change: {:?}", change.get_branch_change());
        change.apply(&mut user0).unwrap();
        user0.commit();

        // Create aggregation
        let mut agg = AggregationContext::new(user0.get_base_art().clone(), Box::new(thread_rng()));

        debug!("agg operation_tree:\n{}", agg.operation_tree.get_root());

        let sk1 = Fr::rand(&mut rng);

        let result = agg.remove_member(&user3_path, sk1);

        assert!(
            matches!(result, Err(ArtError::InvalidMergeInput)),
            "Fail to get Error ArtError::InvalidMergeInput. Instead got {:?}.",
            result
        );
    }

    #[test]
    fn test_branch_aggregation_with_leave() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let group_length = 7;
        let secrets = (0..group_length)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let mut user0 = PrivateZeroArt::new(user0, Box::new(thread_rng())).unwrap();
        let mut user1 = PrivateArt::<CortadoAffine>::new(
            user0.get_base_art().get_public_art().clone(),
            secrets[1],
        )
        .unwrap();

        let target_3 = user0
            .get_base_art()
            .get_public_art()
            .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
            .unwrap();
        let target_3_index = NodeIndex::Direction(target_3.to_vec());
        // Create aggregation
        let mut agg = AggregationContext::new(user0.base_art.clone(), Box::new(thread_rng()));

        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.remove_member(&target_3_index, Fr::rand(&mut rng))
            .unwrap();
        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.add_member(Fr::rand(&mut rng)).unwrap();
        agg.leave_group(Fr::rand(&mut rng)).unwrap();

        let plain_agg =
            ChangeAggregation::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

        plain_agg.apply(&mut user1).unwrap();

        assert_eq!(&agg.operation_tree, &user1);
    }

    #[test]
    fn test_branch_aggregation_from_one_node() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);

        let user0 = PrivateZeroArt::new(
            PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let mut pub_art = user0.get_base_art().get_public_art().clone();

        let mut agg = AggregationContext::new(user0.base_art.clone(), Box::new(thread_rng()));
        agg.add_member(Fr::rand(&mut rng)).unwrap();

        agg.update_key(Fr::rand(&mut rng)).unwrap();

        agg.update_key(Fr::rand(&mut rng)).unwrap();

        agg.update_key(Fr::rand(&mut rng)).unwrap();

        let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();
        plain_agg.apply(&mut pub_art).unwrap();

        assert_eq!(&pub_art, agg.operation_tree.get_public_art())
    }

    #[test]
    fn test_branch_aggregation_for_one_update() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(
            PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap(),
            user0_rng,
        )
        .unwrap();

        let mut pub_art = user0.get_base_art().get_public_art().clone();

        let mut agg = AggregationContext::new(user0.base_art.clone(), Box::new(thread_rng()));
        agg.add_member(Fr::rand(&mut rng)).unwrap();

        let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();

        plain_agg.apply(&mut user0).unwrap();
        plain_agg.apply(&mut pub_art).unwrap();

        assert_eq!(
            &pub_art,
            user0.get_upstream_art().get_public_art(),
            "They are:\n{}\nand\n{}",
            pub_art.get_root(),
            user0.get_upstream_art().get_public_art().get_root()
        )
    }
}
