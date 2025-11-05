use ark_ec::{AffineRepr};
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use zrt_zk::aggregated_art::ProverAggregationTree;
use zrt_zk::art::{ArtProof};
use zrt_zk::EligibilityArtefact;
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt};
use crate::art::{ArtAdvancedOps, PublicZeroArt};
use crate::changes::aggregations::{AggregatedChange, ChangeAggregation, ProverAggregationData};
use crate::changes::{ApplicableChange, ProvableChange};
use crate::errors::ArtError;
use crate::node_index::NodeIndex;

pub struct AggregationContext<T, G>
where
    G: AffineRepr,
{
    pub(crate) prover_aggregation: ChangeAggregation<ProverAggregationData<G>>,
    pub(crate) operation_tree: T,
}

impl<T, G> AggregationContext<T, G>
where
    G: AffineRepr,
{
    pub fn new(operation_tree: T) -> Self {
        Self {
            prover_aggregation: Default::default(),
            operation_tree,
        }
    }
}

impl<R> ArtAdvancedOps<CortadoAffine, ()> for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn add_member(&mut self, new_key: Fr) -> Result<(), ArtError> {
        self.prover_aggregation.add_member(new_key, &mut self.operation_tree)?;

        Ok(())
    }

    fn remove_member(&mut self, target_leaf: &NodeIndex, new_key: Fr) -> Result<(), ArtError> {
        self.prover_aggregation.remove_member(&target_leaf.get_path()?, new_key, &mut self.operation_tree)?;

        Ok(())
    }

    fn leave_group(&mut self, new_key: Fr) -> Result<(), ArtError> {
        self.prover_aggregation.leave(new_key, &mut self.operation_tree)?;

        Ok(())
    }

    fn update_key(&mut self, new_key: Fr) -> Result<(), ArtError> {
        self.prover_aggregation.update_key(new_key, &mut self.operation_tree)?;

        Ok(())
    }
}

impl<R> ApplicableChange<PublicArt<CortadoAffine>, CortadoAffine> for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PublicArt<CortadoAffine>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::<CortadoAffine>::try_from(&self.prover_aggregation)?;
        plain_aggregation.update_public_art(art)
    }
}

impl<R> ApplicableChange<PrivateArt<CortadoAffine>, CortadoAffine> for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateArt<CortadoAffine>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(&self.prover_aggregation)?;
        plain_aggregation.update_private_art(art)
    }
}

impl<R> ApplicableChange<PublicZeroArt<CortadoAffine>, CortadoAffine> for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PublicZeroArt<CortadoAffine>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(&self.prover_aggregation)?;
        plain_aggregation.update_public_art(&mut art.upstream_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>, CortadoAffine> for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: ?Sized + Rng,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(&self.prover_aggregation)?;
        plain_aggregation.update_private_art(&mut art.private_art)
    }
}

impl<R> ProvableChange for AggregationContext<PrivateZeroArt<R>, CortadoAffine>
where
    R: Rng + ?Sized
{
    fn prove(&self, ad: &[u8], eligibility: Option<EligibilityArtefact>) -> Result<ArtProof, ArtError>
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => {
                EligibilityArtefact::Owner((
                    self.operation_tree.get_leaf_secret_key(),
                    self.operation_tree.get_leaf_public_key())
                )
            }
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = self.operation_tree.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok(proof)
    }
}

impl<'a, R> TryFrom<&'a AggregationContext<PrivateZeroArt<R>, CortadoAffine>> for ProverAggregationTree<CortadoAffine>
where
    R: Rng + ?Sized,
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<PrivateZeroArt<R>, CortadoAffine>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

impl<'a, R> TryFrom<&'a AggregationContext<PrivateZeroArt<R>, CortadoAffine>> for AggregatedChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<PrivateZeroArt<R>, CortadoAffine>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

#[cfg(test)]
mod tests {
    use std::ops::Mul;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{thread_rng, SeedableRng};
    use ark_std::UniformRand;
    use cortado::{CortadoAffine, Fr};
    use zrt_zk::aggregated_art::ProverAggregationTree;
    use crate::art::{AggregationContext, ArtAdvancedOps};
    use crate::art::art_node::LeafIterWithPath;
    use crate::art::art_types::{PrivateArt, PrivateZeroArt};
    use crate::changes::aggregations::{AggregatedChange, AggregationData, AggregationNodeIterWithPath, ChangeAggregation, ProverAggregationData, VerifierAggregationData};
    use crate::changes::ApplicableChange;
    use crate::errors::ArtError;
    use crate::helper_tools::iota_function;
    use crate::node_index::NodeIndex;
    use crate::test_helper_tools::init_tracing;
    use crate::TreeMethods;

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
        let user1_rng = Box::new(thread_rng());
        let mut user1 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[2]).unwrap(),
            user1_rng,
        );

        let user2_rng = Box::new(thread_rng());
        let mut user2 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[3]).unwrap(),
            user2_rng,
        );

        let user1_2rng = Box::new(thread_rng());
        let user1_2 = user1.clone_without_rng(user1_2rng);

        let user3_rng = Box::new(thread_rng());
        let mut user3 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[4]).unwrap(),
            user3_rng,
        );
        let user4_rng = Box::new(thread_rng());
        let mut user4 = PrivateZeroArt::new(
            PrivateArt::new(user0.get_public_art().clone(), secrets[5]).unwrap(),
            user4_rng,
        );

        // Create aggregation
        let mut agg = AggregationContext::new(user1.clone());

        let sk1 = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let sk3 = Fr::rand(&mut rng);
        let sk4 = Fr::rand(&mut rng);

        agg.remove_member(&user3.get_node_index(), sk1)
            .unwrap();

        agg.remove_member(&user4.get_node_index(), sk1)
            .unwrap();

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
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.get_root(),
            );
        }

        let root_clone = user1.get_root().clone();
        let leaf_iter = LeafIterWithPath::new(&root_clone).skip(10).take(10);
        for (_, path) in leaf_iter {
            let path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            agg.remove_member(&NodeIndex::Direction(path), Fr::rand(&mut rng))
                .unwrap();

            let aggregation = AggregatedChange::try_from(&agg).unwrap();
            let verifier_aggregation = aggregation.add_co_path(user2.get_public_art()).unwrap();

            let user2_clone_rng = Box::new(thread_rng());
            let mut user2_clone = user2.clone_without_rng(user2_clone_rng);
            aggregation.apply(&mut user2_clone).unwrap();

            assert_eq!(
                agg.operation_tree,
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.get_root(),
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
                user2_clone,
                "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
                agg.operation_tree.get_root(),
                user2_clone.get_root(),
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
            ChangeAggregation::<VerifierAggregationData<CortadoAffine>>::try_from(&agg.prover_aggregation).unwrap();

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
            .add_co_path(user2.get_public_art())
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
            user1_clone,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_clone\n{}",
            agg.operation_tree.get_root(),
            user1_clone.get_root(),
        );

        assert_eq!(
            agg.operation_tree,
            user2,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser2\n{}",
            agg.operation_tree.get_root(),
            user2.get_root(),
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

        let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let mut user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(user0, user0_rng);

        let user3_path = NodeIndex::from(
            user0
                .get_public_art()
                .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[4]).into_affine())
                .unwrap(),
        );
        user0
            .remove_member(&user3_path, Fr::rand(&mut rng))
            .unwrap();

        // Create aggregation
        let mut agg = AggregationContext::new(user0);

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
        let mut user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(user0, user0_rng);
        let mut user1 =
            PrivateArt::<CortadoAffine>::new(user0.get_public_art().clone(), secrets[1]).unwrap();

        let target_3 = user0
            .get_public_art()
            .get_path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
            .unwrap();
        let target_3_index = NodeIndex::Direction(target_3.to_vec());
        // Create aggregation
        let mut agg = AggregationContext::new(user0.clone());

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

        assert_eq!(agg.operation_tree.get_private_art(), &user1);
    }

    #[test]
    fn test_branch_aggregation_from_one_node() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let user0 = PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap();
        let mut user0_rng = Box::new(thread_rng());
        let mut user0 = PrivateZeroArt::new(user0, user0_rng);

        let mut pub_art = user0.get_public_art().clone();

        let mut prover_rng = thread_rng();
        let mut agg = AggregationContext::new(user0);
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
        );

        let mut pub_art = user0.get_public_art().clone();

        let mut agg = ChangeAggregation::<ProverAggregationData<CortadoAffine>>::default();
        agg.add_member(Fr::rand(&mut rng), &mut user0).unwrap();

        let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();

        plain_agg.apply(&mut pub_art).unwrap();

        assert_eq!(
            &pub_art,
            user0.get_public_art(),
            "They are:\n{}\nand\n{}",
            pub_art.get_root(),
            user0.get_public_art().get_root()
        )
    }
}