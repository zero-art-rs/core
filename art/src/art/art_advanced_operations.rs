use crate::art::art_node::LeafStatus;
use crate::art::art_types::PrivateArt;
use crate::art::{AggregationContext, ArtBasicOps, PrivateZeroArt};
use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::NodeIndex;
use crate::tree_methods::TreeMethods;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use zrt_zk::EligibilityArtefact;

pub trait ArtAdvancedOps<G, R>
where
    G: AffineRepr,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<R, ArtError>;

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<R, ArtError>;
}

impl<G> ArtAdvancedOps<G, BranchChange<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        self.add_node(new_key).map(|mut change| {
            change.change_type = BranchChangeType::AddMember;
            change
        })
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<BranchChange<G>, ArtError> {
        let path = target_leaf.get_path()?;
        let append_changes = matches!(
            self.get_node_at(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        let change = self
            .update_node_key(target_leaf, new_key, append_changes)
            .map(|mut change| {
                change.change_type = BranchChangeType::RemoveMember;
                change
            })?;

        self.get_mut_node_at(&path)?.set_status(LeafStatus::Blank)?;

        if !append_changes {
            self.public_art.update_branch_weight(&path, false)?;
        }

        Ok(change)
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        let index = self.get_node_index().clone();
        let change = self
            .update_node_key(&index, new_key, false)
            .map(|mut change| {
                change.change_type = BranchChangeType::Leave;
                change
            })?;

        self.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        Ok(change)
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
        let index = self.get_node_index().clone();
        self.update_node_key(&index, new_key, false)
    }
}

impl<G, R> ArtAdvancedOps<G, ()> for AggregationContext<PrivateArt<G>, G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        self.prover_aggregation.inner_add_member(
            new_key,
            &mut self.operation_tree,
            &mut self.rng,
        )?;

        Ok(())
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(), ArtError> {
        self.prover_aggregation.inner_remove_member(
            &target_leaf.get_path()?,
            new_key,
            &mut self.operation_tree,
            &mut self.rng,
        )?;

        Ok(())
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        self.prover_aggregation.inner_leave_group(
            new_key,
            &mut self.operation_tree,
            &mut self.rng,
        )?;

        Ok(())
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        self.prover_aggregation.inner_update_key(
            new_key,
            &mut self.operation_tree,
            &mut self.rng,
        )?;

        Ok(())
    }
}

impl<R> ArtAdvancedOps<CortadoAffine, PrivateBranchChange<CortadoAffine>>
    for PrivateZeroArt<CortadoAffine, R>
where
    R: Rng + ?Sized,
{
    fn add_member(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        self.add_node(new_key)
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
    ) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        let path = target_leaf.get_path()?;
        let eligibility = if matches!(
            self.base_art.get_node_at(&path)?.get_status(),
            Some(LeafStatus::Active)
        ) {
            let sk = self.base_art.get_leaf_secret_key();
            let pk = self.base_art.get_leaf_public_key();
            EligibilityArtefact::Owner((sk, pk))
        } else {
            let sk = self.base_art.get_root_secret_key();
            let pk = self.base_art.get_root().get_public_key();
            EligibilityArtefact::Member((sk, pk))
        };

        let change = self
            .update_node_key(target_leaf, new_key, false)
            .map(|mut change| {
                change.branch_change.change_type = BranchChangeType::RemoveMember;
                change.eligibility = eligibility;
                change
            })?;

        Ok(change)
    }

    fn leave_group(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        let index = self.base_art.get_node_index().clone();
        let output = self
            .update_node_key(&index, new_key, false)
            .map(|mut output| {
                output.branch_change.change_type = BranchChangeType::Leave;
                output
            })?;

        Ok(output)
    }

    fn update_key(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
        let index = self.upstream_art.get_node_index().clone();
        self.update_node_key(&index, new_key, false)
    }
}

#[cfg(test)]
mod tests {
    use crate::TreeMethods;
    use crate::art::{AggregationContext, PrivateZeroArt};
    use crate::art::art_advanced_operations::ArtAdvancedOps;
    use crate::art::art_node::{LeafIterWithPath, LeafStatus};
    use crate::art::art_types::{PrivateArt, PublicArt};
    use crate::changes::aggregations::{
        AggregatedChange, AggregationData, AggregationNodeIterWithPath, AggregationTree,
        ProverAggregationData, VerifierAggregationData,
    };
    use crate::changes::{ApplicableChange, ProvableChange, VerifiableChange};
    use crate::errors::ArtError;
    use crate::helper_tools::iota_function;
    use crate::init_tracing;
    use crate::node_index::{Direction, NodeIndex};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::ops::{Add, Mul};
    use std::rc::Rc;
    use tracing::{debug, warn};
    use zkp::rand::thread_rng;
    use zrt_zk::EligibilityRequirement;
    use zrt_zk::aggregated_art::ProverAggregationTree;

    const DEFAULT_TEST_GROUP_SIZE: usize = 100;

    #[test]
    fn test_flow_append_join_update() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::setup(&vec![secret_key_0]).unwrap();
        assert_eq!(
            user0.get_leaf_public_key(),
            CortadoAffine::generator().mul(secret_key_0).into_affine(),
            "New node is in the art, and it is on the correct path.",
        );

        // Add member with user0
        let secret_key_1 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        let changes = user0.add_member(secret_key_1).unwrap();
        // debug!("user0\n{}", user0.get_root());

        assert_eq!(
            user0
                .get_node(&changes.node_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(secret_key_1).into_affine(),
            "New node is in the art, and it is on the correct path.",
        );
        assert_eq!(
            user0
                .get_node(&user0.get_node_index())
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(secret_key_0).into_affine(),
            "User node is isn't changed, after append member request.",
        );
        assert_ne!(
            user0
                .get_node(&changes.node_index)
                .unwrap()
                .get_public_key(),
            user0
                .get_node(&user0.get_node_index())
                .unwrap()
                .get_public_key(),
            "Sanity check: Both users nodes have different public key.",
        );

        // Serialise and deserialize art for the new user.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        assert_ne!(secret_key_0, secret_key_1);
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();
        let mut user1 = PrivateArt::new(public_art, secret_key_1).unwrap();
        // debug!("user1\n{}", user1.get_root());

        assert_ne!(
            user0.secrets, user1.secrets,
            "Sanity check: Both users have different path secrets"
        );
        assert!(user0.eq(&user1), "New user received the same art");
        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );

        let tk0 = user0.get_root_secret_key();
        let tk1 = user1.get_root_secret_key();

        let secret_key_3 = Fr::rand(&mut rng);

        // New user updates his key
        let change_key_update = user1.update_key(secret_key_3).unwrap();
        let tk2 = user1.get_root_secret_key();
        assert_ne!(
            tk1,
            user1.get_root_secret_key(),
            "Sanity check: old tk is different from the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet"
        );
        assert_eq!(user1.get_leaf_secret_key(), secret_key_3,);

        change_key_update.apply(&mut user0).unwrap();
        assert_eq!(
            user0
                .get_node(&changes.node_index)
                .unwrap()
                .get_public_key(),
            user1.get_leaf_public_key(),
        );

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_ne!(
            tk2, tk1,
            "Sanity check: old tk is different from the new one."
        );
    }

    /// Creator, after computing the art with several users, removes the target_user. The
    /// remaining users updates their art, and one of them, also removes target_user (instead
    /// or changing, he merges two updates). Removed user fails to update his art.
    #[test]
    fn test_removal_of_the_same_user() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        let mut user2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

        let mut user3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

        assert!(user0.eq(&user1), "New user received the same art");
        assert!(user0.eq(&user2), "New user received the same art");
        assert!(user0.eq(&user3), "New user received the same art");

        let tk0 = user0.get_root_secret_key();
        let tk1 = user1.get_root_secret_key();
        let tk2 = user2.get_root_secret_key();
        let tk3 = user2.get_root_secret_key();

        let blanking_secret_key_1 = Fr::rand(&mut rng);
        let blanking_secret_key_2 = Fr::rand(&mut rng);

        // User0 removes second user node from the art.
        let remove_member_change1 = user0
            .remove_member(&user2.get_node_index(), blanking_secret_key_1)
            .unwrap();
        let tk_r1 = user0.get_root_secret_key();
        assert_ne!(
            tk1, tk_r1,
            "Sanity check: old tk is different from the stored one."
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
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1)
                .into_affine(),
            "The node was removed correctly."
        );

        // Sync other users art
        remove_member_change1.apply(&mut user1).unwrap();
        remove_member_change1.apply(&mut user3).unwrap();

        let err = remove_member_change1.apply(&mut user2).err();
        assert!(
            matches!(err, Some(ArtError::InapplicableBlanking)),
            "Must fail to perform art update using blank leaf, but got {:?}.",
            err
        );

        assert_eq!(
            user0,
            user1,
            "Both users have the same view on the state of the art, but have: user0:\n{},\nuser1:\n{}",
            user0.get_root(),
            user1.get_root(),
        );
        assert_eq!(
            user0, user3,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1)
                .into_affine(),
            "The node was removed correctly."
        );

        // User1 removes second user node from the art.
        let remove_member_change2 = user1
            .remove_member(&user2.get_node_index(), blanking_secret_key_2)
            .unwrap();
        let tk_r2 = user1.get_root_secret_key();
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&remove_member_change2.node_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1 + blanking_secret_key_2)
                .into_affine(),
            "The node was removed correctly."
        );
        assert_eq!(
            user1.get_root().get_public_key(),
            CortadoAffine::generator().mul(tk_r2).into_affine(),
            "The node was removed correctly."
        );
        assert_ne!(
            tk_r1, tk_r2,
            "Sanity check: old tk is different from the new one."
        );
        assert_eq!(
            tk_r2,
            user1.get_root_secret_key(),
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
        remove_member_change2.apply(&mut user0).unwrap();
        remove_member_change2.apply(&mut user3).unwrap();

        assert_eq!(
            user0.get_root_secret_key(),
            user1.get_root_secret_key(),
            "Both users have the same view on the state of the art"
        );

        assert_eq!(
            user0, user1,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user0, user3,
            "Both users have the same view on the state of the art"
        );
        assert_eq!(
            user1
                .get_public_art()
                .get_node(&remove_member_change1.node_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(blanking_secret_key_1 + blanking_secret_key_2)
                .into_affine(),
            "The node was removed correctly."
        );
    }

    #[test]
    fn test_art_key_update() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let main_user_id = 0;
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let private_art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
        let public_art = private_art.public_art.clone();

        let mut users_arts = Vec::new();
        for i in 0..DEFAULT_TEST_GROUP_SIZE as usize {
            users_arts.push(PrivateArt::new(public_art.clone(), secrets[i]).unwrap());
        }

        let root_key = private_art.get_root_secret_key();
        for i in 0..DEFAULT_TEST_GROUP_SIZE as usize {
            // Assert creator and users computed the same tree key.
            assert_eq!(users_arts[i].get_root_secret_key(), root_key);
        }

        let mut main_user_art = users_arts[main_user_id].clone();

        // Save old secret key to roll back
        let main_old_key = secrets[main_user_id];
        let main_new_key = Fr::rand(&mut rng);
        let changes = main_user_art.update_key(main_new_key).unwrap();
        assert_ne!(main_user_art.get_leaf_secret_key(), main_old_key);

        let mut pub_keys = Vec::new();
        let mut parent = main_user_art.get_root();
        for direction in &main_user_art.get_node_index().get_path().unwrap() {
            pub_keys.push(parent.get_child(*direction).unwrap().get_public_key());
            parent = parent.get_child(*direction).unwrap();
        }
        pub_keys.reverse();

        for (secret_key, corr_pk) in main_user_art.secrets.iter().zip(pub_keys.iter()) {
            assert_eq!(
                CortadoAffine::generator().mul(secret_key).into_affine(),
                *corr_pk,
                "Multiplication done correctly."
            );
        }

        let test_user_id = 12;
        changes.apply(&mut users_arts[test_user_id]).unwrap();
        let new_key = main_user_art.get_root_secret_key();
        assert_eq!(users_arts[test_user_id].get_root_secret_key(), new_key);

        let changes = main_user_art.update_key(main_old_key).unwrap();
        let recomputed_old_key = main_user_art.get_root_secret_key();

        assert_eq!(root_key, recomputed_old_key);

        for i in 0..DEFAULT_TEST_GROUP_SIZE as usize {
            if i != main_user_id {
                changes.apply(&mut users_arts[i]).unwrap();
                assert_eq!(users_arts[i].get_root_secret_key(), recomputed_old_key);
            }
        }
    }

    /// Main user creates art with four users, then first, second, and third users updates their
    /// arts. The forth user, applies changes, but swaps first two.
    #[test]
    fn test_wrong_update_ordering() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        assert_ne!(secret_key_1, secret_key_2);
        assert_ne!(secret_key_2, secret_key_3);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        let mut user2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_2).unwrap();

        let mut user3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_3).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let key_update_change0 = user0.update_key(new_sk0).unwrap();
        let tk_r0 = user0.get_root_secret_key();
        assert_eq!(
            tk_r0,
            user0.get_root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User1 updates his art.
        key_update_change0.apply(&mut user1).unwrap();
        let new_sk1 = Fr::rand(&mut rng);
        let key_update_change1 = user1.update_key(new_sk1).unwrap();
        let tk_r1 = user1.get_root_secret_key();
        assert_eq!(
            tk_r1,
            user1.get_root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User2 updates his art.
        key_update_change0.apply(&mut user2).unwrap();
        key_update_change1.apply(&mut user2).unwrap();
        let new_sk2 = Fr::rand(&mut rng);
        let key_update_change2 = user2.update_key(new_sk2).unwrap();
        let tk_r2 = user2.get_root_secret_key();
        assert_eq!(
            tk_r2,
            user2.get_root_secret_key(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Update art for other users.
        key_update_change1.apply(&mut user3).unwrap();
        key_update_change0.apply(&mut user3).unwrap();
        key_update_change2.apply(&mut user3).unwrap();

        assert_ne!(
            user3.get_root(),
            user2.get_root(),
            "Wrong order of updates will bring to different public arts."
        );
    }

    /// The same key update, shouldn't affect the art, as it will be overwritten by itself.
    #[test]
    fn test_apply_key_update_changes_twice() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();
        let def_tk = user0.get_root_secret_key();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let key_update_change0 = user0.update_key(new_sk0).unwrap();
        let tk_r0 = user0.get_root_secret_key();

        // Update art for other users.
        key_update_change0.apply(&mut user1).unwrap();
        key_update_change0.apply(&mut user1).unwrap();

        assert_eq!(
            user0, user1,
            "Applying of the same key update twice, will give no affect."
        );
    }

    #[test]
    fn test_correctness_for_method_from() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

        let user1_2 = PrivateArt::restore(public_art.clone(), user1.get_secrets().clone()).unwrap();

        assert_eq!(user1, user1_2);

        assert_eq!(user1.get_secrets(), user1_2.get_secrets());
    }

    #[test]
    fn test_get_node() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let leaf_secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut user0: PrivateArt<CortadoAffine> = PrivateArt::setup(&leaf_secrets).unwrap();

        let random_public_key = CortadoAffine::rand(&mut rng);
        assert!(user0.get_node_with(random_public_key).is_err());
        assert!(
            user0
                .get_public_art()
                .get_leaf_with(random_public_key)
                .is_err()
        );

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf = user0.get_public_art().get_leaf_with(pk).unwrap();
            assert_eq!(leaf.get_public_key(), pk);
            assert!(leaf.is_leaf());
        }

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf = user0.get_public_art().get_node_with(pk).unwrap();
            assert_eq!(leaf.get_public_key(), pk);
        }

        for sk in &leaf_secrets {
            let pk = CortadoAffine::generator().mul(sk).into_affine();
            let leaf_path = user0.get_public_art().get_path_to_leaf_with(pk).unwrap();
            let leaf = user0
                .get_public_art()
                .get_node(&NodeIndex::Direction(leaf_path))
                .unwrap();
            assert_eq!(leaf.get_public_key(), pk);

            assert!(leaf.is_leaf());
        }
    }

    #[test]
    fn test_apply_key_update_to_itself() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);
        let secret_key_1 = Fr::rand(&mut rng);
        let secret_key_2 = Fr::rand(&mut rng);
        let secret_key_3 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::<CortadoAffine>::setup(&vec![
            secret_key_0,
            secret_key_1,
            secret_key_2,
            secret_key_3,
        ])
        .unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_0).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let key_update_change0 = user0.update_key(new_sk0).unwrap();

        // User1 fails to update his art.
        assert!(matches!(
            key_update_change0.apply(&mut user1),
            Err(ArtError::InapplicableKeyUpdate)
        ));
    }

    #[test]
    fn test_art_weights_after_one_add_member() {
        init_tracing();

        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut tree: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 1..DEFAULT_TEST_GROUP_SIZE {
            let _ = tree.add_member(Fr::rand(&mut rng)).unwrap();
        }

        for node in tree.get_root() {
            if node.is_leaf() {
                if !matches!(node.get_status(), Some(LeafStatus::Active)) {
                    assert_eq!(node.get_weight(), 0);
                } else {
                    assert_eq!(node.get_weight(), 1);
                }
            } else {
                assert_eq!(
                    node.get_weight(),
                    node.get_child(Direction::Left).unwrap().get_weight()
                        + node.get_child(Direction::Right).unwrap().get_weight()
                );
            }
        }
    }

    #[test]
    fn test_weights_correctness_for_make_blank() {
        init_tracing();
        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..9)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();


        let mut user0 = PrivateZeroArt::new(
            PrivateArt::setup(&secrets).unwrap(),
            Box::new(thread_rng()),
        ).unwrap();
        let target_user_path = user0.get_path_to_leaf_with(
            CortadoAffine::generator().mul(secrets[3]).into_affine(),
        ).unwrap();
        let target_user_index = NodeIndex::from(target_user_path);

        let change = user0.remove_member(&target_user_index, Fr::rand(&mut rng)).unwrap().branch_change;
        change.apply(&mut user0).unwrap();
        assert!(user0.stashed_confirm_removals.is_empty());
        user0.commit().unwrap();

        assert_eq!(user0.get_root().get_weight() + 1, secrets.len());

        for node in user0.get_root() {
            if node.is_leaf() {
                if !matches!(node.get_status(), Some(LeafStatus::Active)) {
                    assert_eq!(node.get_weight(), 0);
                } else {
                    assert_eq!(node.get_weight(), 1);
                }
            } else {
                assert_eq!(
                    node.get_weight(),
                    node.get_child(Direction::Left).unwrap().get_weight()
                        + node.get_child(Direction::Right).unwrap().get_weight()
                );
            }
        }
    }

    #[test]
    fn test_leaf_status_affect_on_make_blank() {
        init_tracing();

        if DEFAULT_TEST_GROUP_SIZE < 2 {
            warn!("Cant run the test test_merge_for_key_updates, as the group size is to small");
            return;
        }

        let seed = rand::random();
        let mut rng = StdRng::seed_from_u64(seed);
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();
        let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();

        let sk_1 = Fr::rand(&mut rng);
        let sk_2 = Fr::rand(&mut rng);
        let user_2_path = art
            .get_public_art()
            .get_path_to_leaf_with(CortadoAffine::generator().mul(&secrets[1]).into_affine())
            .unwrap();
        let user_2_index = NodeIndex::from(user_2_path.clone());

        // usual update
        let mut art1 = art.clone();
        art1.remove_member(&user_2_index, sk_1).unwrap();
        art1.remove_member(&user_2_index, sk_2).unwrap();
        assert_eq!(
            art1.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art2 = art.clone();
        art2.public_art
            .get_mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::PendingRemoval)
            .unwrap();
        art2.remove_member(&user_2_index, sk_1).unwrap();
        art2.remove_member(&user_2_index, sk_2).unwrap();
        assert_eq!(
            art2.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator().mul(&(sk_1 + sk_2)).into_affine()
        );

        let mut art3 = art.clone();
        art3.public_art
            .get_mut_node(&user_2_index)
            .unwrap()
            .set_status(LeafStatus::Blank)
            .unwrap();
        art3.remove_member(&user_2_index, sk_1).unwrap();
        art3.remove_member(&user_2_index, sk_2).unwrap();
        assert_eq!(
            art3.get_public_art()
                .get_node(&user_2_index)
                .unwrap()
                .get_public_key(),
            CortadoAffine::generator()
                .mul(&(secrets[1] + sk_1 + sk_2))
                .into_affine()
        );
    }
}
