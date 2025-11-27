use crate::art::private_art::tests::{owner_leaf_eligibility_artefact, verify_secrets_are_correct};
use crate::art::{AggregationContext, ArtAdvancedOps, PrivateArt};
use crate::art_node::{LeafIterWithPath, TreeMethods};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregatedChange, AggregationData, AggregationNodeIterWithPath, AggregationTree,
    VerifierAggregationData,
};
use crate::errors::ArtError;
use crate::helper_tools::iota_function;
use crate::node_index::NodeIndex;
use crate::test_helper_tools::init_tracing;
use ark_ec::{AffineRepr, CurveGroup};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::UniformRand;
use ark_std::rand::prelude::StdRng;
use ark_std::rand::{SeedableRng, thread_rng};
use cortado::{CortadoAffine, Fr};
use std::ops::Mul;
use zrt_zk::EligibilityRequirement;
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};
use zrt_zk::art::ArtProof;
use zrt_zk::engine::{ZeroArtProverEngine, ZeroArtVerifierEngine};

#[test]
fn test_aggregation_serialization() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);

    let user0 = PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap();

    let mut agg = AggregationContext::from(user0.clone());
    for _ in 0..8 {
        agg.add_member(Fr::rand(&mut rng)).unwrap();
    }

    let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();

    let bytes = postcard::to_allocvec(&plain_agg).unwrap();
    let retrieved_agg: AggregatedChange<CortadoAffine> = postcard::from_bytes(&bytes).unwrap();

    assert_eq!(retrieved_agg, plain_agg);
}

/// Test if non-mergable changes (without blank for the second time) can be aggregated and
/// applied correctly.
#[test]
fn test_branch_aggregation_flow() {
    init_tracing();

    // Init test context.
    let mut rng: StdRng = StdRng::seed_from_u64(0);
    let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

    let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

    // Serialise and deserialize art for the other users.
    let user1 = PrivateArt::new(user0.public_art().clone(), secrets[0]).unwrap();
    let mut user2 = PrivateArt::new(user0.public_art().clone(), secrets[1]).unwrap();
    let user3 = PrivateArt::new(user0.public_art().clone(), secrets[4]).unwrap();
    let user4 = PrivateArt::new(user0.public_art().clone(), secrets[5]).unwrap();

    let user1_2 = user1.clone();

    // Create aggregation
    let mut agg = AggregationContext::from(user1.clone());

    let sk1 = Fr::rand(&mut rng);
    let sk2 = Fr::rand(&mut rng);
    let sk3 = Fr::rand(&mut rng);
    let sk4 = Fr::rand(&mut rng);
    let sk5 = Fr::rand(&mut rng);

    agg.remove_member(&user3.node_index(), sk1).unwrap();
    agg.remove_member(&user4.node_index(), sk1).unwrap();
    agg.add_member(sk2).unwrap();
    agg.add_member(sk3).unwrap();
    agg.add_member(sk4).unwrap();
    // agg.add_member(sk5).unwrap();

    let mut user2_clone = user2.clone();
    let aggregation = AggregatedChange::try_from(&agg).unwrap();
    aggregation.apply(&mut user2_clone).unwrap();
    user2_clone.commit().unwrap();

    verify_secrets_are_correct(&user2_clone).unwrap();
    verify_secrets_are_correct(&agg.operation_tree).unwrap();

    assert_eq!(
        agg.operation_tree.root(),
        user2_clone.root(),
        "Both users have the same view on the state of the public art.\nUser1\n{}\nUser1_2\n{}\ndefault user 2:\n{}\naggregation:\n{}",
        agg.operation_tree.root(),
        user2_clone.root(),
        user2.root(),
        agg.prover_aggregation.root.unwrap()
    );

    assert_eq!(
        agg.operation_tree.root_secret_key(),
        user2_clone.root_secret_key(),
        "Both users have the same view on the state of the art.\nUser1\n{:#?}\nUser1_2\n{:#?}\naggregation:\n{}",
        agg.operation_tree.secrets,
        user2_clone.secrets,
        agg.prover_aggregation.root.unwrap()
    );

    assert_eq!(
        agg.operation_tree,
        user2_clone,
        "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}\naggregation:\n{}",
        agg.operation_tree.root(),
        user2_clone.root(),
        agg.prover_aggregation.root.unwrap()
    );

    // Check successful ProverAggregationTree conversion to tree_ds tree
    let tree_ds_tree = ProverAggregationTree::<CortadoAffine>::try_from(&agg);
    assert!(tree_ds_tree.is_ok());

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
                .mul(iota_function(&co_public_key.mul(node.data.secret_key).into_affine()).unwrap())
                .into_affine();
            assert_eq!(parent.data.public_key, pk);
        }
    }

    for _ in 0..10 {
        let sk_i = Fr::rand(&mut rng);
        agg.add_member(sk_i).unwrap();

        let aggregation = AggregatedChange::try_from(&agg).unwrap();

        let mut user2_clone = user2.clone();
        aggregation.apply(&mut user2_clone).unwrap();
        user2_clone.commit().unwrap();

        assert_eq!(
            agg.operation_tree.root(),
            user2_clone.root(),
            "Both users have the same view on the state of the public art.\nUser1\n{}\nUser1_2\n{}\ndefault user 2:\n{}\naggregation:\n{}",
            agg.operation_tree.root(),
            user2_clone.root(),
            user2.root(),
            agg.prover_aggregation.root.unwrap()
        );

        verify_secrets_are_correct(&user2_clone).unwrap();
        verify_secrets_are_correct(&agg.operation_tree).unwrap();

        assert_eq!(
            agg.operation_tree.root_secret_key(),
            user2_clone.root_secret_key(),
            "Both users have the same view on the state of the art.\nUser1\n{:#?}\nUser1_2\n{:#?}\naggregation:\n{}",
            agg.operation_tree.secrets,
            user2_clone.secrets,
            agg.prover_aggregation.root.unwrap()
        );

        assert_eq!(
            agg.operation_tree,
            user2_clone,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
            agg.operation_tree.root(),
            user2_clone.root(),
        );
    }

    let root_clone = user1.root().clone();
    let leaf_iter = LeafIterWithPath::new(&root_clone).skip(10).take(10);
    for (_, path) in leaf_iter {
        let path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
        agg.remove_member(&NodeIndex::Direction(path), Fr::rand(&mut rng))
            .unwrap();

        let aggregation = AggregatedChange::try_from(&agg).unwrap();
        let verifier_aggregation = aggregation.add_co_path(user2.public_art()).unwrap();

        let user2_clone_rng = Box::new(thread_rng());
        let mut user2_clone = user2.clone();
        aggregation.apply(&mut user2_clone).unwrap();
        user2_clone.commit().unwrap();

        assert_eq!(
            agg.operation_tree,
            user2_clone,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
            agg.operation_tree.root(),
            user2_clone.root(),
        );
    }

    for _ in 0..100 {
        let sk_i = Fr::rand(&mut rng);
        agg.add_member(sk_i).unwrap();

        let aggregation = AggregatedChange::try_from(&agg).unwrap();

        let user2_clone_rng = Box::new(thread_rng());
        let mut user2_clone = user2.clone();
        aggregation.apply(&mut user2_clone).unwrap();
        user2_clone.commit().unwrap();

        assert_eq!(
            agg.operation_tree,
            user2_clone,
            "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_2\n{}",
            agg.operation_tree.root(),
            user2_clone.root(),
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
                .mul(iota_function(&co_public_key.mul(node.data.secret_key).into_affine()).unwrap())
                .into_affine();
            assert_eq!(parent.data.public_key, pk);
        }
    }

    let verifier_aggregation = AggregationTree::<VerifierAggregationData<CortadoAffine>>::try_from(
        &agg.prover_aggregation,
    )
    .unwrap();

    let aggregation_from_prover =
        AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

    let aggregation_from_verifier =
        AggregationTree::<AggregationData<CortadoAffine>>::try_from(&verifier_aggregation).unwrap();

    assert_eq!(
        aggregation_from_prover, aggregation_from_verifier,
        "Aggregations are equal from both sources."
    );

    let extracted_verifier_aggregation = aggregation_from_prover
        .add_co_path(user2.public_art())
        .unwrap();

    assert_eq!(
        verifier_aggregation, extracted_verifier_aggregation,
        "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
        verifier_aggregation, extracted_verifier_aggregation,
    );

    let mut user1_clone: PrivateArt<ark_ec::short_weierstrass::Affine<cortado::Parameters>> =
        user1_2.clone();
    agg.apply(&mut user1_clone).unwrap();
    user1_clone.commit().unwrap();
    agg.apply(&mut user2).unwrap();
    user2.commit().unwrap();

    assert_eq!(
        agg.operation_tree,
        user1_clone,
        "Both users have the same view on the state of the art.\nUser1\n{}\nUser1_clone\n{}",
        agg.operation_tree.root(),
        user1_clone.root(),
    );

    assert_eq!(
        agg.operation_tree,
        user2,
        "Both users have the same view on the state of the art.\nUser1\n{}\nUser2\n{}",
        agg.operation_tree.root(),
        user2.root(),
    );
}

#[test]
fn test_fail_on_branch_aggregation_with_commit_removal() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let group_length = 78;
    let secrets = (0..group_length)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let base_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let user0_rng = Box::new(thread_rng());
    let mut user0 = base_art;

    let user3_path = NodeIndex::from(
        user0
            .root()
            .path_to_leaf_with(CortadoAffine::generator().mul(secrets[4]).into_affine())
            .unwrap(),
    );
    let (_, change, _) = user0
        .remove_member(&user3_path, Fr::rand(&mut rng))
        .unwrap();
    change.apply(&mut user0).unwrap();
    user0.commit().unwrap();

    // Create aggregation
    let mut agg = AggregationContext::from(user0.clone());

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
    let group_length = 97;
    let secrets = (0..group_length)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let user0 = user0;
    let mut user1 =
        PrivateArt::<CortadoAffine>::new(user0.public_art().clone(), secrets[1]).unwrap();

    let target_3 = user0
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    let target_3_index = NodeIndex::Direction(target_3.to_vec());

    // Create aggregation
    let mut agg = AggregationContext::from(user0.clone());

    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.remove_member(&target_3_index, Fr::rand(&mut rng))
        .unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.leave_group(Fr::rand(&mut rng)).unwrap();

    let plain_agg = AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

    plain_agg.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    assert_eq!(&agg.operation_tree, &user1);
}

#[test]
fn test_empty_aggregation() {
    init_tracing();

    let mut rng = StdRng::seed_from_u64(0);

    let user0 = PrivateArt::setup(&vec![Fr::rand(&mut rng)]).unwrap();

    let mut public_art = user0.public_art().clone();

    let agg = AggregationContext::from(user0.clone());
    let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();

    let apply_result = plain_agg.apply(&mut public_art);
    assert!(
        matches!(apply_result, Ok(())),
        "Get {:?} wile expecting Ok(())",
        apply_result,
    );
}

#[test]
fn test_branch_aggregation_from_one_node() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let user0 = PrivateArt::<CortadoAffine>::setup(&vec![Fr::rand(&mut rng)]).unwrap();
    let mut pub_art = user0.public_art().clone();

    let mut agg = AggregationContext::from(user0.clone());

    agg.add_member(Fr::rand(&mut rng)).unwrap();
    agg.update_key(Fr::rand(&mut rng)).unwrap();
    agg.update_key(Fr::rand(&mut rng)).unwrap();
    agg.update_key(Fr::rand(&mut rng)).unwrap();

    let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();
    plain_agg.apply(&mut pub_art).unwrap();
    pub_art.commit().unwrap();

    assert_eq!(
        &pub_art,
        agg.operation_tree.public_art(),
        "Trees are different. Public art is\n{}\nwhile operation tree is:\n{}",
        &pub_art.root(),
        agg.operation_tree.public_art().root()
    )
}

#[test]
fn test_branch_aggregation_for_one_update() {
    init_tracing();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);

    let secrets = vec![Fr::rand(&mut rng)];
    let mut user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

    let mut pub_art = user0.public_art().clone();

    let mut agg = AggregationContext::from(user0.clone());
    agg.add_member(Fr::rand(&mut rng)).unwrap();

    let plain_agg = AggregatedChange::<CortadoAffine>::try_from(&agg).unwrap();

    plain_agg.apply(&mut user0).unwrap();
    plain_agg.apply(&mut pub_art).unwrap();
    user0.commit().unwrap();
    pub_art.commit().unwrap();

    assert_eq!(
        &pub_art,
        user0.public_art(),
        "They are:\n{}\nand\n{}",
        pub_art.root(),
        user0.public_art().root()
    );

    assert_eq!(secrets[0], user0.leaf_secret_key());

    let sk = Fr::rand(&mut rng);
    let (_, private_branch_change, _) = user0.update_key(sk).unwrap();

    sk.apply(&mut user0).unwrap();
    private_branch_change.apply(&mut pub_art).unwrap();

    user0.commit().unwrap();
    pub_art.commit().unwrap();
}

#[test]
fn test_branch_aggregation_proof_verify() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let group_length = 7;
    let secrets = (0..group_length)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let mut user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let mut user0_rng = Box::new(thread_rng());
    let mut user1 =
        PrivateArt::<CortadoAffine>::new(user0.public_art().clone(), secrets[1]).unwrap();

    let target_3 = user0
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    // Create aggregation
    let mut agg = AggregationContext::from(user0.clone());

    for i in 0..4 {
        agg.add_member(Fr::rand(&mut rng)).unwrap();
    }

    let associated_data = b"data";

    let mut proof_bytes = Vec::new();
    prover_engine
        .new_context(owner_leaf_eligibility_artefact(&user0))
        .for_aggregation(&ProverAggregationTree::try_from(&agg).unwrap())
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap()
        .serialize_compressed(&mut proof_bytes)
        .unwrap();

    // agg.prove(associated_data, None)
    //     .unwrap()
    //     .serialize_compressed(&mut proof_bytes)
    //     .unwrap();

    let plain_agg = AggregatedChange::try_from(&agg).unwrap();

    let aux_pk = user0.leaf_public_key();
    let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
    let decoded_proof = ArtProof::deserialize_compressed(&*proof_bytes).unwrap();

    let extracted_agg = plain_agg.add_co_path(user0.public_art()).unwrap();
    let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg).unwrap();
    verifier_engine
        .new_context(eligibility_requirement)
        .for_aggregation(&verifier_tree)
        .with_associated_data(associated_data)
        .verify(&decoded_proof)
        .unwrap();

    // plain_agg
    //     .verify(
    //         &user0,
    //         associated_data,
    //         eligibility_requirement,
    //         &decoded_proof,
    //     )
    //     .unwrap();

    let plain_agg = AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

    let fromed_agg = AggregationTree::<VerifierAggregationData<CortadoAffine>>::try_from(
        &agg.prover_aggregation,
    )
    .unwrap();

    let extracted_agg = plain_agg
        .add_co_path(&agg.operation_tree.public_art())
        .unwrap();
    assert_eq!(
        fromed_agg, extracted_agg,
        "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
        fromed_agg, extracted_agg,
    );

    plain_agg.apply(&mut user1).unwrap();
    user1.commit();

    assert_eq!(agg.operation_tree, user1);
}

#[test]
fn test_branch_aggregation_with_public_art() {
    init_tracing();

    let prover_engine = ZeroArtProverEngine::default();
    let verifier_engine = ZeroArtVerifierEngine::default();

    // Init test context.
    let mut rng = StdRng::seed_from_u64(0);
    let group_length = 7;
    let secrets = (0..group_length)
        .map(|_| Fr::rand(&mut rng))
        .collect::<Vec<_>>();

    let user0 = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    let mut user0_rng = Box::new(thread_rng());
    let mut user0 = user0;
    let mut user1 =
        PrivateArt::<CortadoAffine>::new(user0.public_art().clone(), secrets[1]).unwrap();

    let target_3 = user0
        .root()
        .path_to_leaf_with(CortadoAffine::generator().mul(secrets[3]).into_affine())
        .unwrap();
    // Create aggregation
    let mut agg = AggregationContext::from(user0.clone());

    for i in 0..4 {
        agg.add_member(Fr::rand(&mut rng)).unwrap();
    }

    let associated_data = b"data";

    let mut proof_bytes = Vec::new();
    // agg.prove(associated_data, None)
    //     .unwrap()
    //     .serialize_compressed(&mut proof_bytes)
    //     .unwrap();

    prover_engine
        .new_context(owner_leaf_eligibility_artefact(&user0))
        .for_aggregation(&ProverAggregationTree::try_from(&agg).unwrap())
        .with_associated_data(associated_data)
        .prove(&mut thread_rng())
        .unwrap()
        .serialize_compressed(&mut proof_bytes)
        .unwrap();

    let plain_agg = AggregatedChange::try_from(&agg).unwrap();

    let aux_pk = user0.leaf_public_key();
    let eligibility_requirement = EligibilityRequirement::Previleged((aux_pk, vec![]));
    let decoded_proof = ArtProof::deserialize_compressed(&*proof_bytes).unwrap();

    let extracted_agg = plain_agg.add_co_path(user0.public_art()).unwrap();
    let verifier_tree = VerifierAggregationTree::try_from(&extracted_agg).unwrap();
    verifier_engine
        .new_context(eligibility_requirement)
        .for_aggregation(&verifier_tree)
        .with_associated_data(associated_data)
        .verify(&decoded_proof)
        .unwrap();

    let plain_agg = AggregationTree::<AggregationData<CortadoAffine>>::try_from(&agg).unwrap();

    let fromed_agg = AggregationTree::<VerifierAggregationData<CortadoAffine>>::try_from(
        &agg.prover_aggregation,
    )
    .unwrap();

    let extracted_agg = plain_agg
        .add_co_path(&agg.operation_tree.public_art())
        .unwrap();
    assert_eq!(
        fromed_agg, extracted_agg,
        "Verifier aggregations are equal from both sources.\nfirst:\n{}\nsecond:\n{}",
        fromed_agg, extracted_agg,
    );

    plain_agg.apply(&mut user1).unwrap();
    user1.commit().unwrap();

    assert_eq!(agg.operation_tree, user1);
}
