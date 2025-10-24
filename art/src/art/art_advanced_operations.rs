use crate::art::art_node::LeafStatus;
use crate::art::art_types::{PrivateArt, PrivateZeroArt};
use crate::art::branch_change::{BranchChange, BranchChangeType, VerifiableBranchChange};
use crate::art::tree_methods::TreeMethods;
use crate::art::{ArtBasicOps, EligibilityProofInput};
use crate::errors::ARTError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use tracing::debug;

pub trait ArtAdvancedOps<G, R>: ArtBasicOps<G, R>
where
    G: AffineRepr,
{
    fn add_member(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn leave_group(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;

    fn update_key(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<R, ARTError>;
}

impl<G> ArtAdvancedOps<G, BranchChange<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn add_member(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        self.add_node(new_key, eligibility_proof_input, ad)
            .map(|mut change| {
                change.change_type = BranchChangeType::AddMember;
                change
            })
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        let path = target_leaf.get_path()?;
        let append_changes = matches!(
            self.get_node_at(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        let change = self
            .update_node_key(
                target_leaf,
                new_key,
                append_changes,
                eligibility_proof_input,
                ad,
            )
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

    fn leave_group(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        let index = self.get_node_index().clone();
        let change = self
            .update_node_key(&index, new_key, false, eligibility_proof_input, ad)
            .map(|mut change| {
                change.change_type = BranchChangeType::Leave;
                change
            })?;

        self.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        Ok(change)
    }

    fn update_key(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChange<G>, ARTError> {
        let index = self.get_node_index().clone();
        self.update_node_key(&index, new_key, false, eligibility_proof_input, ad)
    }
}

impl<'a, R> ArtAdvancedOps<CortadoAffine, VerifiableBranchChange> for PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    fn add_member(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let change = self
            .add_node(new_key, eligibility_proof_input, ad)
            .map(|mut change| {
                change.branch_change.change_type = BranchChangeType::AddMember;
                change
            })?;

        let mut update_path = change.branch_change.node_index.get_path()?;
        if let None = update_path.pop() {
            return Err(ARTError::EmptyART);
        };

        Ok(change)
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let path = target_leaf.get_path()?;
        let append_changes = matches!(
            self.get_node_at(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        let change = self
            .update_node_key(
                target_leaf,
                new_key,
                append_changes,
                eligibility_proof_input,
                ad,
            )
            .map(|mut change| {
                change.branch_change.change_type = BranchChangeType::RemoveMember;
                change
            })?;

        self.get_mut_node_at(&path)?.set_status(LeafStatus::Blank)?;

        if !append_changes {
            self.private_art
                .public_art
                .update_branch_weight(&path, false)?;
        }

        Ok(change)
    }

    fn leave_group(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let index = self.private_art.get_node_index().clone();
        let change = self
            .update_node_key(&index, new_key, false, eligibility_proof_input, ad)
            .map(|mut change| {
                change.branch_change.change_type = BranchChangeType::Leave;
                change
            })?;

        self.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        Ok(change)
    }

    fn update_key(
        &mut self,
        new_key: Fr,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<VerifiableBranchChange, ARTError> {
        let index = self.private_art.get_node_index().clone();
        self.update_node_key(&index, new_key, false, eligibility_proof_input, ad)
    }
}

#[cfg(test)]
mod tests {
    use crate::art::applicable_change::ApplicableChange;
    use crate::art::art_advanced_operations::ArtAdvancedOps;
    use crate::art::art_node::LeafStatus;
    use crate::art::art_types::{PrivateArt, PublicArt};
    use crate::art::tree_methods::TreeMethods;
    use crate::errors::ARTError;
    use crate::init_tracing;
    use crate::node_index::{Direction, NodeIndex};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::ops::Mul;

    const DEFAULT_TEST_GROUP_SIZE: i32 = 100;

    #[test]
    fn test_flow_append_join_update() {
        init_tracing();

        // Init test context.
        let mut rng = StdRng::seed_from_u64(0);
        let secret_key_0 = Fr::rand(&mut rng);

        let mut user0 = PrivateArt::setup(&vec![secret_key_0]).unwrap();
        // debug!("user0\n{}", user0.get_root());

        // Add member with user0
        let secret_key_1 = Fr::rand(&mut rng);
        assert_ne!(secret_key_0, secret_key_1);
        let changes = user0.add_member(secret_key_1, None, &[]).unwrap();
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

        let tk0 = user0.get_root_secret_key().unwrap();
        let tk1 = user1.get_root_secret_key().unwrap();

        let secret_key_3 = Fr::rand(&mut rng);

        // New user updates his key
        let change_key_update = user1.update_key(secret_key_3, None, &[]).unwrap();
        let tk2 = user1.get_root_secret_key().unwrap();
        assert_ne!(
            tk1,
            user1.get_root_secret_key().unwrap(),
            "Sanity check: old tk is different from the stored one."
        );
        assert_ne!(
            user0, user1,
            "Both users have different view on the state of the art, as they are not synced yet"
        );

        change_key_update.update(&mut user0).unwrap();

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

        let tk0 = user0.get_root_secret_key().unwrap();
        let tk1 = user1.get_root_secret_key().unwrap();
        let tk2 = user2.get_root_secret_key().unwrap();
        let tk3 = user2.get_root_secret_key().unwrap();

        let blanking_secret_key_1 = Fr::rand(&mut rng);
        let blanking_secret_key_2 = Fr::rand(&mut rng);

        // User0 removes second user node from the art.
        let remove_member_change1 = user0
            .remove_member(&user2.get_node_index(), blanking_secret_key_1, None, &[])
            .unwrap();
        let tk_r1 = user0.get_root_secret_key().unwrap();
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
        remove_member_change1.update(&mut user1).unwrap();
        remove_member_change1.update(&mut user3).unwrap();

        let err = remove_member_change1.update(&mut user2).err();
        assert!(
            matches!(err, Some(ARTError::InapplicableBlanking)),
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
            .remove_member(&user2.get_node_index(), blanking_secret_key_2, None, &[])
            .unwrap();
        let tk_r2 = user1.get_root_secret_key().unwrap();
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
            user1.get_root_secret_key().unwrap(),
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
        remove_member_change2.update(&mut user0).unwrap();
        remove_member_change2.update(&mut user3).unwrap();

        assert_eq!(
            user0.get_root_secret_key().ok(),
            user1.get_root_secret_key().ok(),
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
        let key_update_change0 = user0.update_key(new_sk0, None, &[]).unwrap();
        let tk_r0 = user0.get_root_secret_key().unwrap();
        assert_eq!(
            tk_r0,
            user0.get_root_secret_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User1 updates his art.
        key_update_change0.update(&mut user1).unwrap();
        let new_sk1 = Fr::rand(&mut rng);
        let key_update_change1 = user1.update_key(new_sk1, None, &[]).unwrap();
        let tk_r1 = user1.get_root_secret_key().unwrap();
        assert_eq!(
            tk_r1,
            user1.get_root_secret_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // User2 updates his art.
        key_update_change0.update(&mut user2).unwrap();
        key_update_change1.update(&mut user2).unwrap();
        let new_sk2 = Fr::rand(&mut rng);
        let key_update_change2 = user2.update_key(new_sk2, None, &[]).unwrap();
        let tk_r2 = user2.get_root_secret_key().unwrap();
        assert_eq!(
            tk_r2,
            user2.get_root_secret_key().unwrap(),
            "Sanity check: new tk is the same as the stored one."
        );

        // Update art for other users.
        key_update_change1.update(&mut user3).unwrap();
        key_update_change0.update(&mut user3).unwrap();
        key_update_change2.update(&mut user3).unwrap();

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
        let def_tk = user0.get_root_secret_key().unwrap();

        // Serialise and deserialize art for the other users.
        let public_art_bytes = to_allocvec(&user0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secret_key_1).unwrap();

        // User0 updates his key.
        let new_sk0 = Fr::rand(&mut rng);
        let key_update_change0 = user0.update_key(new_sk0, None, &[]).unwrap();
        let tk_r0 = user0.get_root_secret_key().unwrap();

        // Update art for other users.
        key_update_change0.update(&mut user1).unwrap();
        key_update_change0.update(&mut user1).unwrap();

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
        let key_update_change0 = user0.update_key(new_sk0, None, &[]).unwrap();

        // User1 fails to update his art.
        assert!(matches!(
            key_update_change0.update(&mut user1),
            Err(ARTError::InapplicableKeyUpdate)
        ));
    }

    #[test]
    fn test_art_weights_after_one_add_member() {
        let mut rng = StdRng::seed_from_u64(0);
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let mut tree: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        for _ in 1..DEFAULT_TEST_GROUP_SIZE {
            let _ = tree.add_member(Fr::rand(&mut rng), None, &[]).unwrap();
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
}
