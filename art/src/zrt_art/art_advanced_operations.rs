use crate::errors::ARTError;
use crate::node_index::NodeIndex;
use crate::zrt_art::art_node::LeafStatus;
use crate::zrt_art::art_types::PrivateArt;
use crate::zrt_art::branch_change::{BranchChanges, BranchChangesType};
use crate::zrt_art::tree_node::TreeMethods;
use crate::zrt_art::{ArtBasicOps, EligibilityProofInput};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
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

impl<G> ArtAdvancedOps<G, BranchChanges<G>> for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn add_member(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let changes = self.add_node(new_key, eligibility_proof_input, ad)?;

        let mut update_path = changes.node_index.get_path()?;
        if let None = update_path.pop() {
            return Err(ARTError::EmptyART);
        };

        self.public_art.update_branch_weight(&update_path, true)?;

        Ok(changes)
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let path = target_leaf.get_path()?;
        let append_changes = matches!(
            self.get_node_at(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        let changes = self.update_node_key(
            target_leaf,
            new_key,
            append_changes,
            eligibility_proof_input,
            ad,
        )?;

        if !append_changes {
            self.public_art.update_branch_weight(&path, false)?;
        }

        Ok(changes)
    }

    fn leave_group(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let index = self.get_node_index().clone();
        let mut changes =
            self.update_node_key(&index, new_key, false, eligibility_proof_input, ad)?;

        self.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;
        changes.change_type = BranchChangesType::Leave;

        Ok(changes)
    }

    fn update_key(
        &mut self,
        new_key: G::ScalarField,
        eligibility_proof_input: Option<EligibilityProofInput>,
        ad: &[u8],
    ) -> Result<BranchChanges<G>, ARTError> {
        let index = self.get_node_index().clone();
        self.update_node_key(&index, new_key, false, eligibility_proof_input, ad)
    }
}

#[cfg(test)]
mod tests {
    use crate::errors::ARTError;
    use crate::init_tracing;
    use crate::zrt_art::applicable_change::ApplicableChange;
    use crate::zrt_art::art_advanced_operations::ArtAdvancedOps;
    use crate::zrt_art::art_types::{PrivateArt, PublicArt};
    use crate::zrt_art::tree_node::TreeMethods;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use postcard::{from_bytes, to_allocvec};
    use std::ops::Mul;
    use tracing::debug;

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
}
