// use crate::art::{ArtUpdateOutput, PrivateArt, PublicArt};
// use crate::art_node::{ArtNode, LeafStatus, TreeMethods};
// use crate::changes::aggregations::AggregationNode;
// use crate::changes::branch_change::{BranchChange, BranchChangeType};
// use crate::errors::ArtError;
// use crate::helper_tools;
// use crate::helper_tools::{default_proof_basis, default_verifier_engine, recompute_artefacts};
// use crate::node_index::{Direction, NodeIndex};
// use ark_ec::AffineRepr;
// use ark_ec::CurveGroup;
// use ark_ff::PrimeField;
// use ark_std::rand::Rng;
// use serde::{Deserialize, Serialize};
// use std::fmt::{Debug, Formatter};
// use std::mem;
// use std::rc::Rc;
// use zrt_zk::engine::{ZeroArtEngineOptions, ZeroArtProverEngine, ZeroArtVerifierEngine};
//
// /// Context for public art operations.
// ///
// /// This structure manages merge changes by having two Art trees. `base_art` with previous state
// /// of the art, and `upstream_art` with current state of the art. When the method `commit()`
// /// is called, `base_art` will be changed to the upstream_art.
// #[derive(Clone, Serialize, Deserialize)]
// #[serde(bound = "")]
// pub struct PublicZeroArt<G>
// where
//     G: AffineRepr,
// {
//     pub(crate) base_art: PublicArt<G>,
//     pub(crate) upstream_art: PublicArt<G>,
//     pub(crate) marker_tree: AggregationNode<bool>,
//     pub(crate) stashed_confirm_removals: Vec<BranchChange<G>>,
//     #[serde(skip, default = "default_verifier_engine")]
//     pub(crate) verifier_engine: ZeroArtVerifierEngine,
// }
//
// impl<G> PublicZeroArt<G>
// where
//     G: AffineRepr,
// {
//     /// Create new art from the provided `base_art`.
//     pub fn new(base_art: PublicArt<G>) -> Result<Self, ArtError> {
//         let upstream_art = base_art.clone();
//         let marker_tree = AggregationNode::<bool>::try_from(base_art.get_root())?;
//
//         Ok(Self {
//             base_art,
//             upstream_art,
//             marker_tree,
//             stashed_confirm_removals: vec![],
//             verifier_engine: default_verifier_engine(),
//         })
//     }
//
//     /// Finishes current epoch. This will apply all the unapplied removal confirms and
//     /// change `base_art` to the `upstream_art`.
//     pub fn commit(&mut self) -> Result<(), ArtError> {
//         let changes = mem::take(&mut self.stashed_confirm_removals);
//         for change in &changes {
//             self.upstream_art
//                 .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;
//         }
//
//         self.marker_tree.data = false;
//         self.base_art = self.upstream_art.clone();
//
//         Ok(())
//     }
//
//     /// Removes all the applied changes from the ART tree by resetting `upstream_art` to `base_art`.
//     pub fn discard(&mut self) {
//         self.marker_tree.data = false;
//         self.upstream_art = self.base_art.clone();
//     }
//
//     pub fn get_base_art(&self) -> &PublicArt<G> {
//         &self.base_art
//     }
//
//     pub fn get_upstream_art(&self) -> &PublicArt<G> {
//         &self.upstream_art
//     }
//
//     pub fn get_mut_upstream_art(&mut self) -> &mut PublicArt<G> {
//         &mut self.upstream_art
//     }
//
//     pub fn recover(
//         base_art: PublicArt<G>,
//         upstream_art: PublicArt<G>,
//         marker_tree: AggregationNode<bool>,
//         stashed_confirm_removals: Vec<BranchChange<G>>,
//     ) -> Self {
//         Self {
//             base_art,
//             upstream_art,
//             marker_tree,
//             stashed_confirm_removals,
//             verifier_engine: default_verifier_engine(),
//         }
//     }
//
//     /// Returns a new art preview, without commiting changes with `commit()`.
//     pub fn get_preview(&self) -> Result<PublicArt<G>, ArtError> {
//         let mut preview = self.upstream_art.clone();
//
//         for change in &self.stashed_confirm_removals {
//             preview.apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;
//
//             helper_tools::change_leaf_status_by_change_type(
//                 preview.get_mut_node_at(&change.node_index.get_path()?)?,
//                 &change.change_type,
//             )?;
//         }
//
//         Ok(preview)
//     }
// }
//
// impl<G> PartialEq for PublicZeroArt<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn eq(&self, other: &Self) -> bool {
//         self.base_art == other.base_art
//             && self.upstream_art == other.upstream_art
//             && self.marker_tree == other.marker_tree
//     }
// }
//
// impl<G> Debug for PublicZeroArt<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("PublicZeroArt")
//             .field("base_art", &self.base_art)
//             .field("upstream_art", &self.upstream_art)
//             .field("marker_tree", &self.marker_tree)
//             .field("stashed_confirm_removals", &self.stashed_confirm_removals)
//             .finish()
//     }
// }
//
// impl<G> Eq for PublicZeroArt<G>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
// }
//
// // TODO: Remove clone
// /// Context for private art operations.
// #[derive(Clone, Serialize)]
// #[serde(bound = "")]
// pub struct PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     pub(crate) base_art: PrivateArt<G>,
//     pub(crate) upstream_art: PrivateArt<G>,
//     pub(crate) marker_tree: AggregationNode<bool>,
//     #[serde(skip)]
//     pub(crate) rng: Box<R>,
//     pub(crate) stashed_confirm_removals: Vec<BranchChange<G>>,
//     #[serde(skip)]
//     pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
//     #[serde(skip)]
//     pub(crate) verifier_engine: ZeroArtVerifierEngine,
// }
//
// impl<G, R> PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     pub fn setup(secrets: &[G::ScalarField], rng: Box<R>) -> Result<Self, ArtError> {
//         let private_art = PrivateArt::setup(secrets)?;
//         Self::new(private_art, rng)
//     }
//
//     pub fn new(base_art: PrivateArt<G>, rng: Box<R>) -> Result<Self, ArtError> {
//         let upstream_art = base_art.clone();
//         let marker_tree = AggregationNode::<bool>::try_from(base_art.get_root())?;
//
//         let proof_basis = default_proof_basis();
//
//         Ok(Self {
//             base_art,
//             upstream_art,
//             marker_tree,
//             rng,
//             stashed_confirm_removals: vec![],
//             prover_engine: Rc::new(ZeroArtProverEngine::new(
//                 proof_basis.clone(),
//                 ZeroArtEngineOptions::default(),
//             )),
//             verifier_engine: ZeroArtVerifierEngine::new(
//                 proof_basis.clone(),
//                 ZeroArtEngineOptions::default(),
//             ),
//         })
//     }
//
//     pub fn into_parts(
//         self,
//     ) -> (
//         PrivateArt<G>,
//         PrivateArt<G>,
//         AggregationNode<bool>,
//         Vec<BranchChange<G>>,
//     ) {
//         (
//             self.base_art,
//             self.upstream_art,
//             self.marker_tree,
//             self.stashed_confirm_removals,
//         )
//     }
//
//     pub fn recover(
//         base_art: PrivateArt<G>,
//         upstream_art: PrivateArt<G>,
//         marker_tree: AggregationNode<bool>,
//         stashed_confirm_removals: Vec<BranchChange<G>>,
//         rng: Box<R>,
//     ) -> Result<Self, ArtError> {
//         let proof_basis = default_proof_basis();
//
//         Ok(Self {
//             base_art,
//             upstream_art,
//             marker_tree,
//             rng,
//             stashed_confirm_removals,
//             prover_engine: Rc::new(ZeroArtProverEngine::new(
//                 proof_basis.clone(),
//                 ZeroArtEngineOptions::default(),
//             )),
//             verifier_engine: ZeroArtVerifierEngine::new(
//                 proof_basis.clone(),
//                 ZeroArtEngineOptions::default(),
//             ),
//         })
//     }
//
//     pub fn clone_without_rng<R2>(&self, rng: Box<R2>) -> PrivateZeroArt<G, R2>
//     where
//         R2: Rng + ?Sized,
//     {
//         PrivateZeroArt {
//             base_art: self.base_art.clone(),
//             upstream_art: self.upstream_art.clone(),
//             marker_tree: self.marker_tree.clone(),
//             rng,
//             stashed_confirm_removals: self.stashed_confirm_removals.clone(),
//             prover_engine: Rc::clone(&self.prover_engine),
//             verifier_engine: self.verifier_engine.clone(),
//         }
//     }
//
//     pub fn get_leaf_secret_key(&self) -> G::ScalarField {
//         self.base_art.secrets[0]
//     }
//
//     pub fn get_root_secret_key(&self) -> G::ScalarField {
//         self.base_art.secrets[self.base_art.secrets.len() - 1]
//     }
//
//     pub fn get_secrets(&self) -> &Vec<G::ScalarField> {
//         &self.base_art.secrets
//     }
//
//     pub fn get_leaf_public_key(&self) -> G {
//         G::generator().mul(self.get_leaf_secret_key()).into_affine()
//     }
//
//     pub fn get_root_public_key(&self) -> G {
//         G::generator().mul(self.get_root_secret_key()).into_affine()
//     }
//
//     pub fn get_base_art(&self) -> &PrivateArt<G> {
//         &self.base_art
//     }
//
//     pub fn get_upstream_art(&self) -> &PrivateArt<G> {
//         &self.upstream_art
//     }
//
//     pub fn get_mut_upstream_art(&mut self) -> &mut PrivateArt<G> {
//         &mut self.upstream_art
//     }
//
//     pub fn get_marker_tree(&self) -> &AggregationNode<bool> {
//         &self.marker_tree
//     }
//
//     pub fn get_node_index(&self) -> &NodeIndex {
//         self.get_base_art().get_node_index()
//     }
//
//     pub fn commit(&mut self) -> Result<(), ArtError> {
//         let changes = mem::take(&mut self.stashed_confirm_removals);
//         for change in &changes {
//             self.upstream_art
//                 .public_art
//                 .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;
//
//             helper_tools::change_leaf_status_by_change_type(
//                 self.upstream_art
//                     .get_mut_node_at(&change.node_index.get_path()?)?,
//                 &change.change_type,
//             )?;
//
//             let updated_secrets = self.get_updated_secrets(change)?;
//             self.upstream_art
//                 .update_secrets_with_merge_bound(&updated_secrets, updated_secrets.len())?;
//         }
//
//         self.marker_tree.data = false;
//         self.base_art = self.upstream_art.clone();
//
//         Ok(())
//     }
//
//     /// Returns a new art preview, without commiting changes to the upstream art.
//     pub fn get_preview(&self) -> Result<PrivateArt<G>, ArtError> {
//         let mut preview = self.upstream_art.clone();
//
//         for change in &self.stashed_confirm_removals {
//             preview
//                 .public_art
//                 .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;
//
//             helper_tools::change_leaf_status_by_change_type(
//                 preview.get_mut_node_at(&change.node_index.get_path()?)?,
//                 &change.change_type,
//             )?;
//
//             let updated_secrets = self.get_updated_secrets(change)?;
//             preview.update_secrets_with_merge_bound(&updated_secrets, updated_secrets.len())?;
//         }
//
//         Ok(preview)
//     }
//
//     pub fn discard(&mut self) {
//         self.marker_tree.data = false;
//         self.upstream_art = self.base_art.clone();
//     }
//
//     /// Returns only new secrets from root to some node.
//     pub(crate) fn get_updated_secrets(
//         &self,
//         changes: &BranchChange<G>,
//     ) -> Result<Vec<G::ScalarField>, ArtError> {
//         let target_art = &self.base_art;
//         let intersection = target_art
//             .get_node_index()
//             .intersect_with(&changes.node_index)?;
//
//         let mut partial_co_path =
//             if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
//                 vec![*public_key]
//             } else {
//                 // else it is or self update or AddMember, which is forbidden.
//                 vec![]
//             };
//         partial_co_path.append(&mut target_art.public_art.get_co_path_values(&intersection)?);
//
//         let level_sk = target_art.secrets
//             [(target_art.secrets.len() - partial_co_path.len()).saturating_sub(1)];
//
//         let secrets = recompute_artefacts(level_sk, &partial_co_path)?.secrets;
//
//         Ok(secrets[1..].to_vec())
//     }
//
//     pub(crate) fn ephemeral_private_add_node(
//         &self,
//         new_key: G::ScalarField,
//     ) -> Result<ArtUpdateOutput<G>, ArtError> {
//         let target_art = self.get_upstream_art();
//         let mut path = target_art.public_art.find_place_for_new_node()?;
//
//         let target_leaf = target_art.get_node_at(&path)?;
//         let target_public_key = target_leaf.public_key();
//
//         if !target_leaf.is_leaf() {
//             return Err(ArtError::LeafOnly);
//         }
//
//         let mut co_path = target_art.get_public_art().get_co_path_values(&path)?;
//
//         let extend_node = matches!(target_leaf.status(), Some(LeafStatus::Active));
//         if extend_node {
//             co_path.insert(0, target_public_key);
//             path.push(Direction::Right);
//         }
//
//         let artefacts = recompute_artefacts(new_key, &co_path)?;
//         let change =
//             artefacts.derive_branch_change(BranchChangeType::AddMember, NodeIndex::from(path))?;
//         let tk = *artefacts.secrets.last().ok_or(ArtError::NoChanges)?;
//
//         Ok((tk, change, artefacts))
//     }
// }
//
// impl<G, R> PartialEq for PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn eq(&self, other: &Self) -> bool {
//         self.base_art == other.base_art
//             && self.upstream_art == other.upstream_art
//             && self.marker_tree == other.marker_tree
//     }
// }
//
// impl<G, R> Eq for PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
// }
//
// impl<G, R> Debug for PrivateZeroArt<G, R>
// where
//     G: AffineRepr,
//     G::BaseField: PrimeField,
//     R: Rng + ?Sized,
// {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("PrivateZeroArt")
//             .field("base_art", &self.base_art)
//             .field("upstream_art", &self.upstream_art)
//             .field("marker_tree", &self.marker_tree)
//             .finish()
//     }
// }
//
// /// Move current node down to left child, and append other node to the right.
// pub(crate) fn extend_marker_node(parent: &mut AggregationNode<bool>, other: bool) {
//     parent.l = Some(Box::new(AggregationNode::from(parent.data)));
//     parent.r = Some(Box::new(AggregationNode::from(other)));
// }
//
// /// Update `secrets` and `node_index` if the user node was moved by the performed member addition.
// pub(crate) fn update_secrets_if_need<G>(
//     upstream_art: &mut PrivateArt<G>,
//     new_node_path: &[Direction],
// ) -> Result<bool, ArtError>
// where
//     G: AffineRepr,
// {
//     // if true, then add member was with extension (instead of replacement).
//     if upstream_art.node_index.is_subpath_of_vec(new_node_path)? {
//         let secret = *upstream_art.secrets.first().ok_or(ArtError::EmptyArt)?;
//
//         upstream_art.secrets.insert(0, secret);
//         upstream_art.node_index.push(Direction::Left);
//         return Ok(true);
//     }
//
//     Ok(false)
// }
//
// /// Extends target node and return true, if target node is leaf. if target node isn't a
// /// leaf, return false.
// pub(crate) fn handle_potential_art_node_extension_on_add_member<G>(
//     upstream_art: &mut PublicArt<G>,
//     target_node_path: &[Direction],
//     last_direction: Direction,
// ) -> Result<bool, ArtError>
// where
//     G: AffineRepr,
// {
//     let parent_art_node = upstream_art.get_mut_node_at(target_node_path)?;
//
//     // if true, then add member was with extension (instead of replacement).
//     if parent_art_node.child(last_direction).is_none() {
//         parent_art_node.extend(ArtNode::default());
//         return Ok(true);
//     }
//
//     Ok(false)
// }
//
// // If marker to the leaf doesn't exists, extend the parent. If parent doesn't exist,
// // return error.
// pub(crate) fn handle_potential_marker_tree_node_extension_on_add_member(
//     marker_tree: &mut AggregationNode<bool>,
//     target_node_path: &[Direction],
//     last_direction: Direction,
// ) -> Result<bool, ArtError> {
//     let parent_marker_node = marker_tree.mut_node(target_node_path)?;
//
//     if parent_marker_node.child(last_direction).is_none() {
//         extend_marker_node(parent_marker_node, true);
//         return Ok(true);
//     }
//
//     Ok(false)
// }
