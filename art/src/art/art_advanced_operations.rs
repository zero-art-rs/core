// use crate::art::{AggregationContext, ArtBasicOps, PrivateZeroArt};
use crate::art::PrivateArt;
use crate::art_node::{LeafStatus, TreeMethods};
use crate::changes::branch_change::{BranchChange, BranchChangeType, PrivateBranchChange};
use crate::errors::ArtError;
use crate::node_index::NodeIndex;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use zrt_zk::EligibilityArtefact;

/// Advanced ART operations like remove member, leave group, update key, etc.
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

// impl<G> ArtAdvancedOps<G, BranchChange<G>> for PrivateArt<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn add_member(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
//         self.add_node(new_key).map(|mut change| {
//             change.change_type = BranchChangeType::AddMember;
//             change
//         })
//     }
//
//     fn remove_member(
//         &mut self,
//         target_leaf: &NodeIndex,
//         new_key: G::ScalarField,
//     ) -> Result<BranchChange<G>, ArtError> {
//         let path = target_leaf.get_path()?;
//         let append_changes = matches!(self.node_at(&path)?.status(), Some(LeafStatus::Blank));
//         let change = self
//             .update_node_key(target_leaf, new_key, append_changes)
//             .map(|mut change| {
//                 change.change_type = BranchChangeType::RemoveMember;
//                 change
//             })?;
//
//         self.mut_node_at(&path)?.set_status(LeafStatus::Blank)?;
//
//         if !append_changes {
//             self.public_art.update_weight(&path, false)?;
//         }
//
//         Ok(change)
//     }
//
//     fn leave_group(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
//         let index = self.get_node_index().clone();
//         let change = self
//             .update_node_key(&index, new_key, false)
//             .map(|mut change| {
//                 change.change_type = BranchChangeType::Leave;
//                 change
//             })?;
//
//         self.get_mut_node(&index)?
//             .set_status(LeafStatus::PendingRemoval)?;
//
//         Ok(change)
//     }
//
//     fn update_key(&mut self, new_key: G::ScalarField) -> Result<BranchChange<G>, ArtError> {
//         let index = self.get_node_index().clone();
//         self.update_node_key(&index, new_key, false)
//     }
// }

// impl<G, R> ArtAdvancedOps<G, ()> for AggregationContext<PrivateArt<G>, G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn add_member(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
//         self.prover_aggregation.inner_add_member(
//             new_key,
//             &mut self.operation_tree,
//             &mut self.rng,
//         )?;
//
//         Ok(())
//     }
//
//     fn remove_member(
//         &mut self,
//         target_leaf: &NodeIndex,
//         new_key: G::ScalarField,
//     ) -> Result<(), ArtError> {
//         self.prover_aggregation.inner_remove_member(
//             &target_leaf.get_path()?,
//             new_key,
//             &mut self.operation_tree,
//             &mut self.rng,
//         )?;
//
//         Ok(())
//     }
//
//     fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
//         self.prover_aggregation.inner_leave_group(
//             new_key,
//             &mut self.operation_tree,
//             &mut self.rng,
//         )?;
//
//         Ok(())
//     }
//
//     fn update_key(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
//         self.prover_aggregation.inner_update_key(
//             new_key,
//             &mut self.operation_tree,
//             &mut self.rng,
//         )?;
//
//         Ok(())
//     }
// }
//
// impl<R> ArtAdvancedOps<CortadoAffine, PrivateBranchChange<CortadoAffine>>
//     for PrivateZeroArt<CortadoAffine, R>
// where
//     R: Rng + ?Sized,
// {
//     fn add_member(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
//         self.add_node(new_key)
//     }
//
//     fn remove_member(
//         &mut self,
//         target_leaf: &NodeIndex,
//         new_key: Fr,
//     ) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
//         let path = target_leaf.get_path()?;
//         let eligibility = if matches!(
//             self.upstream_art.get_node_at(&path)?.status(),
//             Some(LeafStatus::Active)
//         ) {
//             let sk = self.upstream_art.get_leaf_secret_key();
//             let pk = self.upstream_art.get_leaf_public_key();
//             EligibilityArtefact::Owner((sk, pk))
//         } else {
//             let sk = self.upstream_art.get_root_secret_key();
//             let pk = self.upstream_art.get_root().public_key();
//             EligibilityArtefact::Member((sk, pk))
//         };
//
//         let change = self
//             .update_node_key(target_leaf, new_key, false)
//             .map(|mut change| {
//                 change.branch_change.change_type = BranchChangeType::RemoveMember;
//                 change.eligibility = eligibility;
//                 change
//             })?;
//
//         Ok(change)
//     }
//
//     fn leave_group(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
//         let index = self.upstream_art.get_node_index().clone();
//         let output = self
//             .update_node_key(&index, new_key, false)
//             .map(|mut output| {
//                 output.branch_change.change_type = BranchChangeType::Leave;
//                 output
//             })?;
//
//         Ok(output)
//     }
//
//     fn update_key(&mut self, new_key: Fr) -> Result<PrivateBranchChange<CortadoAffine>, ArtError> {
//         let index = self.upstream_art.get_node_index().clone();
//         self.update_node_key(&index, new_key, false)
//     }
// }