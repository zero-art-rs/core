use crate::TreeMethods;
use crate::art::ArtUpdateOutput;
use crate::art::art_node::{ArtNode, LeafStatus};
use crate::art::art_types::{PrivateArt, PublicArt};
use crate::changes::aggregations::AggregationNode;
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{default_proof_basis, default_verifier_engine, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::rc::Rc;
use serde::{Deserialize, Serialize};
use zrt_zk::engine::{ZeroArtEngineOptions, ZeroArtProverEngine, ZeroArtVerifierEngine};

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct PublicZeroArt<G>
where
    G: AffineRepr,
{
    pub(crate) base_art: PublicArt<G>,
    pub(crate) upstream_art: PublicArt<G>,
    pub(crate) marker_tree: AggregationNode<bool>,
    pub(crate) stashed_confirm_removals: Vec<BranchChange<G>>,
    #[serde(skip, default = "default_verifier_engine")]
    pub(crate) verifier_engine: ZeroArtVerifierEngine,
}

impl<G> PublicZeroArt<G>
where
    G: AffineRepr,
{
    pub fn new(base_art: PublicArt<G>) -> Result<Self, ArtError> {
        let upstream_art = base_art.clone();
        let marker_tree = AggregationNode::<bool>::try_from(base_art.get_root())?;

        Ok(Self {
            base_art,
            upstream_art,
            marker_tree,
            stashed_confirm_removals: vec![],
            verifier_engine: default_verifier_engine(),
        })
    }

    pub fn commit(&mut self) -> Result<(), ArtError> {
        let changes = mem::take(&mut self.stashed_confirm_removals);
        for change in &changes {
            self.upstream_art
                .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;
        }

        self.marker_tree.data = false;
        self.base_art = self.upstream_art.clone();

        Ok(())
    }

    pub fn discard(&mut self) {
        self.marker_tree.data = false;
        self.upstream_art = self.base_art.clone();
    }

    pub fn get_upstream_art(&self) -> &PublicArt<G> {
        &self.upstream_art
    }

    pub fn get_mut_upstream_art(&mut self) -> &mut PublicArt<G> {
        &mut self.upstream_art
    }

    pub fn recover(
        base_art: PublicArt<G>,
        upstream_art: PublicArt<G>,
        marker_tree: AggregationNode<bool>,
        stashed_confirm_removals: Vec<BranchChange<G>>,
    ) -> Self {
        Self {
            base_art,
            upstream_art,
            marker_tree,
            stashed_confirm_removals,
            verifier_engine: default_verifier_engine(),
        }
    }

    /// Returns a new art preview, without commiting changes to the upstream art.
    pub fn get_new_art_preview(&self) -> Result<PublicArt<G>, ArtError> {
        let mut preview = self.upstream_art.clone();

        for change in &self.stashed_confirm_removals {
            preview
                .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;

            PublicArt::change_leaf_status_by_change_type(
                preview
                    .get_mut_node_at(&change.node_index.get_path()?)?,
                &change.change_type,
            )?;

        }

        Ok(preview)
    }
}

impl<G> PartialEq for PublicZeroArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        self.base_art == other.base_art
            && self.upstream_art == other.upstream_art
            && self.marker_tree == other.marker_tree
    }
}

impl<G> Debug for PublicZeroArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicZeroArt")
            .field("base_art", &self.base_art)
            .field("upstream_art", &self.upstream_art)
            .field("marker_tree", &self.marker_tree)
            .field("stashed_confirm_removals", &self.stashed_confirm_removals)
            .finish()
    }
}

impl<G> Eq for PublicZeroArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
}

// TODO: Remove clone
#[derive(Clone, Serialize)]
#[serde(bound = "")]
pub struct PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    pub(crate) base_art: PrivateArt<G>,
    pub(crate) upstream_art: PrivateArt<G>,
    pub(crate) marker_tree: AggregationNode<bool>,
    #[serde(skip)]
    pub(crate) rng: Box<R>,
    pub(crate) stashed_confirm_removals: Vec<BranchChange<G>>,
    #[serde(skip)]
    pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
    #[serde(skip)]
    pub(crate) verifier_engine: ZeroArtVerifierEngine,
}

impl<G, R> PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    pub fn new(base_art: PrivateArt<G>, rng: Box<R>) -> Result<Self, ArtError> {
        let upstream_art = base_art.clone();
        let marker_tree = AggregationNode::<bool>::try_from(base_art.get_root())?;

        let proof_basis = default_proof_basis();

        Ok(Self {
            base_art,
            upstream_art,
            marker_tree,
            rng,
            stashed_confirm_removals: vec![],
            prover_engine: Rc::new(ZeroArtProverEngine::new(
                proof_basis.clone(),
                ZeroArtEngineOptions::default(),
            )),
            verifier_engine: ZeroArtVerifierEngine::new(
                proof_basis.clone(),
                ZeroArtEngineOptions::default(),
            ),
        })
    }

    pub fn recover(
        base_art: PrivateArt<G>,
        upstream_art: PrivateArt<G>,
        marker_tree: AggregationNode<bool>,
        stashed_confirm_removals: Vec<BranchChange<G>>,
        rng: Box<R>,
    ) -> Result<Self, ArtError> {
        let proof_basis = default_proof_basis();

        Ok(Self {
            base_art,
            upstream_art,
            marker_tree,
            rng,
            stashed_confirm_removals,
            prover_engine: Rc::new(ZeroArtProverEngine::new(
                proof_basis.clone(),
                ZeroArtEngineOptions::default(),
            )),
            verifier_engine: ZeroArtVerifierEngine::new(
                proof_basis.clone(),
                ZeroArtEngineOptions::default(),
            ),
        })
    }

    pub fn clone_without_rng<R2>(&self, rng: Box<R2>) -> PrivateZeroArt<G, R2>
    where
        R2: Rng + ?Sized,
    {
        PrivateZeroArt {
            base_art: self.base_art.clone(),
            upstream_art: self.upstream_art.clone(),
            marker_tree: self.marker_tree.clone(),
            rng,
            stashed_confirm_removals: self.stashed_confirm_removals.clone(),
            prover_engine: Rc::clone(&self.prover_engine),
            verifier_engine: self.verifier_engine.clone(),
        }
    }

    pub fn get_base_art(&self) -> &PrivateArt<G> {
        &self.base_art
    }

    pub fn get_upstream_art(&self) -> &PrivateArt<G> {
        &self.upstream_art
    }

    pub fn get_mut_upstream_art(&mut self) -> &mut PrivateArt<G> {
        &mut self.upstream_art
    }

    pub fn get_marker_tree(&self) -> &AggregationNode<bool> {
        &self.marker_tree
    }

    pub fn get_node_index(&self) -> &NodeIndex {
        self.get_base_art().get_node_index()
    }

    pub fn commit(&mut self) -> Result<(), ArtError> {
        let changes = mem::take(&mut self.stashed_confirm_removals);
        for change in &changes {
            self.upstream_art
                .public_art
                .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;

            PublicArt::change_leaf_status_by_change_type(
                self.upstream_art
                    .get_mut_node_at(&change.node_index.get_path()?)?,
                &change.change_type,
            )?;

            let updated_secrets = self.get_updated_secrets(change)?;
            self.update_secrets(&updated_secrets, true)?;
        }

        self.marker_tree.data = false;
        self.base_art = self.upstream_art.clone();

        Ok(())
    }

    /// Returns a new art preview, without commiting changes to the upstream art.
    pub fn get_new_art_preview(&self) -> Result<PrivateArt<G>, ArtError> {
        let mut preview = self.upstream_art.clone();

        for change in &self.stashed_confirm_removals {
            preview
                .public_art
                .apply_as_merge_conflict(&change.public_keys, &change.node_index.get_path()?)?;

            PublicArt::change_leaf_status_by_change_type(
                preview
                    .get_mut_node_at(&change.node_index.get_path()?)?,
                &change.change_type,
            )?;

            let updated_secrets = self.get_updated_secrets(change)?;
            preview.update_secrets(&updated_secrets, true)?;
        }

        Ok(preview)
    }

    pub fn discard(&mut self) {
        self.marker_tree.data = false;
        self.upstream_art = self.base_art.clone();
    }

    /// Returns only new secrets from root to some node.
    pub(crate) fn get_updated_secrets(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<Vec<G::ScalarField>, ArtError> {
        let target_art = &self.base_art;
        let intersection = target_art
            .get_node_index()
            .intersect_with(&changes.node_index)?;

        let mut partial_co_path =
            if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
                vec![*public_key]
            } else {
                // else it is or self update or AddMember, which is forbidden.
                vec![]
            };
        partial_co_path.append(&mut target_art.public_art.get_co_path_values(&intersection)?);

        let level_sk = target_art.secrets
            [(target_art.secrets.len() - partial_co_path.len()).saturating_sub(1)];

        let secrets = recompute_artefacts(level_sk, &partial_co_path)?.secrets;

        Ok(secrets[1..].to_vec())
    }

    pub(crate) fn update_secrets(
        &mut self,
        updated_secrets: &[G::ScalarField],
        merge_key: bool,
    ) -> Result<(), ArtError> {
        self.upstream_art.update_secrets(updated_secrets, merge_key)
    }

    pub(crate) fn ephemeral_private_add_node(
        &self,
        new_key: G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ArtError> {
        let target_art = self.get_upstream_art();
        let mut path = match target_art.public_art.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => target_art.public_art.find_path_to_lowest_leaf()?,
        };

        let target_leaf = target_art.get_node_at(&path)?;
        let target_public_key = target_leaf.get_public_key();

        if !target_leaf.is_leaf() {
            return Err(ArtError::LeafOnly);
        }

        let mut co_path = target_art.get_public_art().get_co_path_values(&path)?;

        let extend_node = matches!(target_leaf.get_status(), Some(LeafStatus::Active));
        if extend_node {
            co_path.insert(0, target_public_key);
            path.push(Direction::Right);
        }

        let artefacts = recompute_artefacts(new_key, &co_path)?;
        let change =
            artefacts.derive_branch_change(BranchChangeType::AddMember, NodeIndex::from(path))?;
        let tk = *artefacts.secrets.last().ok_or(ArtError::NoChanges)?;

        Ok((tk, change, artefacts))
    }
}

impl<G, R> PartialEq for PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn eq(&self, other: &Self) -> bool {
        self.base_art == other.base_art
            && self.upstream_art == other.upstream_art
            && self.marker_tree == other.marker_tree
    }
}

impl<G, R> Eq for PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
}

impl<G, R> Debug for PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateZeroArt")
            .field("base_art", &self.base_art)
            .field("upstream_art", &self.upstream_art)
            .field("marker_tree", &self.marker_tree)
            .finish()
    }
}

/// Move current node down to left child, and append other node to the right.
pub(crate) fn extend_marker_node(parent: &mut AggregationNode<bool>, other: bool) {
    parent.l = Some(Box::new(AggregationNode::from(parent.data)));
    parent.r = Some(Box::new(AggregationNode::from(other)));
}

pub(crate) fn insert_first_secret_at_start_if_need<G>(
    upstream_art: &mut PrivateArt<G>,
    target_node_path: &[Direction],
) -> Result<bool, ArtError>
where
    G: AffineRepr,
{
    // if true, then add member was with extension (instead of replacement).
    if upstream_art
        .node_index
        .is_subpath_of_vec(target_node_path)?
    {
        let secret = *upstream_art
            .secrets
            .first()
            .ok_or(ArtError::EmptyArt)?;

        upstream_art.secrets.insert(0, secret);
        return Ok(true);
    }

    Ok(false)
}

/// Extends target node and return true, if target node is leaf. if target node isn't a
/// leaf, return false.
pub(crate) fn handle_potential_art_node_extension_on_add_member<G>(
    upstream_art: &mut PublicArt<G>,
    target_node_path: &[Direction],
    last_direction: Direction,
) -> Result<bool, ArtError>
where
    G: AffineRepr,
{
    let parent_art_node = upstream_art.get_mut_node_at(target_node_path)?;

    // if true, then add member was with extension (instead of replacement).
    if parent_art_node.get_child(last_direction).is_none() {
        parent_art_node.extend(ArtNode::default());
        return Ok(true);
    }

    Ok(false)
}

// If marker to the leaf doesn't exists, extend the parent. If parent doesn't exist,
// return error.
pub(crate) fn handle_potential_marker_tree_node_extension_on_add_member(
    marker_tree: &mut AggregationNode<bool>,
    target_node_path: &[Direction],
    last_direction: Direction,
) -> Result<bool, ArtError> {
    let parent_marker_node = marker_tree.get_mut_node(target_node_path)?;

    if parent_marker_node.get_child(last_direction).is_none() {
        extend_marker_node(parent_marker_node, true);

        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod test {
    use crate::TreeMethods;
    use crate::art::art_types::{PrivateArt, PublicArt};
    use crate::art::{ArtAdvancedOps, PrivateZeroArt};
    use crate::changes::ApplicableChange;
    use crate::changes::branch_change::BranchChange;
    use crate::init_tracing;
    use crate::node_index::{Direction, NodeIndex};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::prelude::StdRng;
    use ark_std::rand::{SeedableRng, thread_rng};
    use cortado::{CortadoAffine, Fr};
    use itertools::Itertools;
    use postcard::{from_bytes, to_allocvec};
    use rand::random;
    use std::ops::{Add, Mul};

    const DEFAULT_TEST_GROUP_SIZE: i32 = 10;

    #[test]
    fn test_if_changes_are_applied_the_same_for_context_and_art() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let mut art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut art1 = PrivateArt::new(art0.public_art.clone(), secrets[1]).unwrap();
        let mut merge_context0 =
            PrivateZeroArt::new(art0.clone(), Box::new(StdRng::seed_from_u64(random()))).unwrap();

        for _ in 0..10 {
            let change = art1.update_key(Fr::rand(&mut rng)).unwrap();

            change.apply(&mut merge_context0).unwrap();
            merge_context0.commit().unwrap();
            change.apply(&mut art0).unwrap();

            assert_eq!(
                &art1,
                &merge_context0.base_art,
                "fail to assert_eq on tree1:\n{}\n and merge context:\n{}",
                &art1.get_root(),
                &merge_context0.base_art.get_root(),
            );
        }
    }

    #[test]
    fn test_apply_usual_change() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut art1 = PrivateArt::new(art0.public_art.clone(), secrets[1]).unwrap();
        let mut merge_context0 =
            PrivateZeroArt::new(art0, Box::new(StdRng::seed_from_u64(random()))).unwrap();

        let change = art1.update_key(Fr::rand(&mut rng)).unwrap();
        change.apply(&mut merge_context0).unwrap();
        merge_context0.commit().unwrap();

        assert_eq!(
            &art1,
            &merge_context0.base_art,
            "fail to assert_eq on tree1:\n{}\n and merge context:\n{}",
            &art1.get_root(),
            &merge_context0.base_art.get_root(),
        );

        let new_sk = Fr::rand(&mut rng);
        let private_change = merge_context0.update_key(new_sk).unwrap();
        let change = private_change.branch_change.clone();
        assert_eq!(new_sk, private_change.secret);

        // change.apply_own_key_update(&mut merge_context0, private_change.get_secret()).unwrap();
        private_change.apply(&mut merge_context0).unwrap();
        merge_context0.commit().unwrap();
        change.apply(&mut art1).unwrap();

        assert_eq!(
            &art1.get_root(),
            &merge_context0.base_art.get_root(),
            "fail to assert_eq on tree1:\n{}\n and merge context:\n{}",
            &art1.get_root(),
            &merge_context0.base_art.get_root(),
        );

        assert_eq!(
            &art1.secrets[1..],
            &merge_context0.base_art.secrets[1..],
            "fail to assert_eq on tree1:\n{:#?}\n and merge context:\n{:#?}",
            &art1.secrets[1..],
            &merge_context0.base_art.secrets[1..],
        );

        assert_eq!(
            &art1,
            &merge_context0.base_art,
            "fail to assert_eq on tree1:\n{}\n and merge context:\n{}",
            &art1.get_root(),
            &merge_context0.base_art.get_root(),
        );
    }

    /// The flow is the next:
    /// - Epoch0: Create art, and init 5 users.
    /// - Epoch1: update key (`user1`, `user2`, `user4`, `user5`), remove target member (`user3`)
    /// - Epoch2:
    #[test]
    fn test_changes_ordering_for_merge() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let def_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

        let mut user0 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        let mut user1 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[1]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        let mut user2 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[2]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        let mut user3 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[3]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        let mut user4 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[4]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        let mut user5 = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[5]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();

        // Perform some changes
        let sk0 = Fr::rand(&mut rng);
        let sk2 = Fr::rand(&mut rng);
        let sk3 = Fr::rand(&mut rng);
        let sk4 = Fr::rand(&mut rng);
        let sk5 = Fr::rand(&mut rng);

        let target_user_public_key = CortadoAffine::generator().mul(secrets[6]).into_affine();
        let target_node_index = NodeIndex::from(
            user3
                .base_art
                .get_path_to_leaf_with(target_user_public_key)
                .unwrap(),
        );

        let private_change1 = user1.update_key(sk0).unwrap();
        let private_change2 = user2.update_key(sk2).unwrap();
        let private_change3 = user3.remove_member(&target_node_index, sk3).unwrap();
        let private_change4 = user4.update_key(sk4).unwrap();
        let private_change5 = user5.update_key(sk5).unwrap();

        let all_but_1_changes: Vec<BranchChange<CortadoAffine>> = vec![
            private_change2.branch_change.clone(),
            private_change3.branch_change.clone(),
            private_change4.branch_change.clone(),
            private_change5.branch_change.clone(),
        ];
        let all_changes = vec![
            private_change1.get_branch_change().clone(),
            private_change2.get_branch_change().clone(),
            private_change3.get_branch_change().clone(),
            private_change4.get_branch_change().clone(),
            private_change5.get_branch_change().clone(),
        ];

        let root_key_pk = private_change1
            .branch_change
            .public_keys
            .first()
            .unwrap()
            .clone()
            + private_change2
                .branch_change
                .public_keys
                .first()
                .unwrap()
                .clone()
            + private_change3
                .branch_change
                .public_keys
                .first()
                .unwrap()
                .clone()
            + private_change4
                .branch_change
                .public_keys
                .first()
                .unwrap()
                .clone()
            + private_change5
                .branch_change
                .public_keys
                .first()
                .unwrap()
                .clone();

        let root_key_pk = root_key_pk.into_affine();

        // Check correctness of the merge
        let mut user0_test_art = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();
        for change in &all_changes {
            change.apply(&mut user0_test_art).unwrap();
        }
        user0_test_art.commit().unwrap();

        let mut user1_test_art = user1.clone();
        private_change1.apply(&mut user1_test_art).unwrap();
        for change in &all_but_1_changes {
            change.apply(&mut user1_test_art).unwrap()
        }
        user1_test_art.commit().unwrap();

        assert_eq!(user0_test_art, user1_test_art,);

        assert_eq!(
            user0_test_art.get_base_art().get_root_public_key(),
            root_key_pk
        );
        assert_eq!(
            user1_test_art.get_base_art().get_root_public_key(),
            root_key_pk
        );

        assert_eq!(
            user1_test_art.upstream_art, user0_test_art.upstream_art,
            "Observer and participant have the same view on the state of the art."
        );

        // check correctness for any permutation for user 0
        for permutation in all_but_1_changes
            .iter()
            .cloned()
            .permutations(all_but_1_changes.len())
        {
            let mut art_1_analog = user1.clone();
            private_change1.apply(&mut art_1_analog).unwrap();
            for change in &permutation {
                change.apply(&mut art_1_analog).unwrap()
            }
            art_1_analog.commit().unwrap();

            assert_eq!(
                art_1_analog,
                user1_test_art,
                "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
                art_1_analog.upstream_art.get_root(),
                user1_test_art.upstream_art.get_root(),
            );
        }

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let mut art_0_analog = PrivateZeroArt::new(
                PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap(),
                Box::new(StdRng::seed_from_u64(random())),
            )
            .unwrap();
            for change in permutation {
                change.apply(&mut art_0_analog).unwrap();
            }
            art_0_analog.commit().unwrap();

            assert_eq!(
                art_0_analog,
                user0_test_art,
                "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
                art_0_analog.upstream_art.get_root(),
                user0_test_art.upstream_art.get_root(),
            );
        }

        let all_users = [
            &mut user0, &mut user1, &mut user2, &mut user3, &mut user4, &mut user5,
        ];
        let all_private_changes = [
            private_change1,
            private_change2,
            private_change3,
            private_change4,
            private_change5,
        ];
        for user in all_users {
            for private_change in &all_private_changes {
                private_change.apply(user).unwrap();
            }
            user.commit().unwrap();
        }

        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);
        assert_eq!(user0, user4);
        assert_eq!(user0, user5);

        // Make more changes with user removal
        let sk0 = Fr::rand(rng);
        let sk1 = Fr::rand(rng);
        let sk2 = Fr::rand(rng);
        let sk3 = Fr::rand(rng);
        let sk4 = Fr::rand(rng);

        let private2_change0 = user0.remove_member(&target_node_index, sk0).unwrap();
        let private2_change1 = user1.update_key(sk1).unwrap();
        let private2_change2 = user2.leave_group(sk2).unwrap();
        let private2_change3 = user3.remove_member(&target_node_index, sk3).unwrap();
        let private2_change4 = user4.update_key(sk4).unwrap();

        let all_changes = vec![
            private2_change0,
            private2_change1,
            private2_change2,
            private2_change3,
        ];

        let mut check_user = user0.clone_without_rng(Box::new(thread_rng()));
        for change in &all_changes {
            change.apply(&mut check_user).unwrap();
        }
        check_user.commit().unwrap();

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let mut art_0_analog = user0.clone_without_rng(Box::new(thread_rng()));
            for change in permutation {
                change.apply(&mut art_0_analog).unwrap();
            }
            art_0_analog.commit().unwrap();

            assert_eq!(
                art_0_analog,
                check_user,
                "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
                art_0_analog.upstream_art.get_root(),
                check_user.upstream_art.get_root(),
            );
        }
    }

    #[test]
    fn test_merge_context_simple_flow() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

        // Serialise and deserialize art for the new user.
        let public_art_bytes = to_allocvec(&art0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        // let mut update_context = PublicUpdateContext::new(public_art.clone());
        let mut update_context1 =
            PrivateZeroArt::new(art0.clone(), Box::new(StdRng::seed_from_u64(random()))).unwrap();

        let mut art0: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[0]).unwrap();

        let mut art1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

        let mut art2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[2]).unwrap();

        let art3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[8]).unwrap();

        let mut update_context3 =
            PrivateZeroArt::new(art3, Box::new(StdRng::seed_from_u64(random()))).unwrap();

        let sk1 = Fr::rand(&mut rng);
        let change1 = art1.update_key(sk1).unwrap();

        let sk2 = Fr::rand(&mut rng);
        let change2 = art2.update_key(sk2).unwrap();

        change1.apply(&mut update_context1).unwrap();
        assert_eq!(
            update_context1.upstream_art.secrets[1..5],
            art1.secrets[1..5],
            "check secrets:\ngot: {:#?}\nshould: {:#?}",
            update_context1.upstream_art.secrets,
            art1.secrets,
        );

        let mut parent = update_context1.upstream_art.get_root();
        // debug!("update_context:\n{}", update_context1.upstream_art.get_root());
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator()
                .mul(update_context1.upstream_art.secrets.last().unwrap().clone())
                .into_affine(),
        );
        for (sk, dir) in update_context1
            .upstream_art
            .secrets
            .iter()
            .take(update_context1.upstream_art.secrets.len() - 1)
            .rev()
            .zip(update_context1.upstream_art.node_index.get_path().unwrap())
        {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }

        change2.apply(&mut update_context1).unwrap();

        change2.apply(&mut update_context3).unwrap();
        change1.apply(&mut update_context3).unwrap();
        assert_eq!(update_context1.upstream_art, update_context3.upstream_art,);
        assert_eq!(update_context1.base_art, update_context3.base_art,);

        let mut parent = update_context1.upstream_art.get_root();
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator()
                .mul(update_context1.upstream_art.secrets.last().unwrap().clone())
                .into_affine(),
        );
        for (sk, dir) in update_context1
            .upstream_art
            .secrets
            .iter()
            .take(update_context1.upstream_art.secrets.len() - 1)
            .rev()
            .zip(update_context1.upstream_art.node_index.get_path().unwrap())
        {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }

        // debug!("art2:\n{}", art2.get_root());
        // debug!("update_context:\n{}", update_context.upstream_art.get_root());
        for i in (2..5).rev() {
            assert_eq!(
                CortadoAffine::generator()
                    .mul(update_context1.upstream_art.secrets[i])
                    .into_affine(),
                CortadoAffine::generator()
                    .mul(art1.secrets[i] + art2.secrets[i])
                    .into_affine(),
            );

            assert_eq!(
                update_context1.upstream_art.secrets[i],
                art1.secrets[i] + art2.secrets[i],
            );
        }

        assert_eq!(
            update_context1.upstream_art.get_root().get_public_key(),
            art1.get_root()
                .get_public_key()
                .add(art2.get_root().get_public_key())
                .into_affine(),
        );

        let path2 = [Direction::Left];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path2)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path2)
                .unwrap()
                .get_public_key()
                .add(art2.get_node_at(&path2).unwrap().get_public_key())
                .into_affine(),
        );

        let path3 = [Direction::Right];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path3)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path3).unwrap().get_public_key()
        );
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path3)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path3).unwrap().get_public_key()
        );

        let path4 = [Direction::Left, Direction::Left];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path4)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path4)
                .unwrap()
                .get_public_key()
                .add(art2.get_node_at(&path4).unwrap().get_public_key())
                .into_affine(),
        );

        let path8 = [Direction::Left, Direction::Left, Direction::Left];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path8)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path8).unwrap().get_public_key(),
        );

        let path9 = [Direction::Left, Direction::Left, Direction::Right];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path9)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path9).unwrap().get_public_key(),
        );

        let path16 = [
            Direction::Left,
            Direction::Left,
            Direction::Left,
            Direction::Left,
        ];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path16)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path16).unwrap().get_public_key(),
        );
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path16)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path16).unwrap().get_public_key(),
        );

        let path17 = [
            Direction::Left,
            Direction::Left,
            Direction::Left,
            Direction::Right,
        ];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path17)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path17).unwrap().get_public_key(),
        );
        assert_ne!(
            update_context1
                .upstream_art
                .get_node_at(&path17)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path17).unwrap().get_public_key(),
        );

        let path18 = [
            Direction::Left,
            Direction::Left,
            Direction::Right,
            Direction::Left,
        ];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path18)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path18).unwrap().get_public_key(),
        );
        assert_ne!(
            update_context1
                .upstream_art
                .get_node_at(&path18)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path18).unwrap().get_public_key(),
        );

        let path19 = [
            Direction::Left,
            Direction::Left,
            Direction::Right,
            Direction::Right,
        ];
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path19)
                .unwrap()
                .get_public_key(),
            art2.get_node_at(&path19).unwrap().get_public_key(),
        );
        assert_eq!(
            update_context1
                .upstream_art
                .get_node_at(&path19)
                .unwrap()
                .get_public_key(),
            art1.get_node_at(&path19).unwrap().get_public_key(),
        );

        update_context1.commit();
        update_context3.commit();
        assert_eq!(update_context1.upstream_art, update_context1.base_art);
        assert_eq!(update_context3.upstream_art, update_context3.base_art);

        let new_sk = Fr::rand(&mut rng);

        let change = update_context3.upstream_art.update_key(new_sk).unwrap();

        let mut parent = update_context1.upstream_art.get_root();
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator()
                .mul(update_context1.upstream_art.secrets.last().unwrap().clone())
                .into_affine(),
        );
        for (sk, dir) in update_context1
            .upstream_art
            .secrets
            .iter()
            .take(update_context1.upstream_art.secrets.len() - 1)
            .rev()
            .zip(update_context1.upstream_art.node_index.get_path().unwrap())
        {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }

        change.apply(&mut update_context1).unwrap();

        // debug!("update_context:\n{}", update_context1.upstream_art.get_root());

        let mut root = update_context1.upstream_art.get_root();
        assert_eq!(
            root.get_public_key(),
            change.public_keys.first().unwrap().clone()
        );
        for (dir, pk) in change
            .node_index
            .get_path()
            .unwrap()
            .iter()
            .zip(&change.public_keys[1..])
        {
            root = root.get_child(*dir).unwrap();

            assert_eq!(root.get_public_key(), *pk);
        }

        let mut parent = update_context1.upstream_art.get_root();
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator()
                .mul(update_context1.upstream_art.secrets.last().unwrap().clone())
                .into_affine(),
        );
        for (sk, dir) in update_context1
            .upstream_art
            .secrets
            .iter()
            .take(update_context1.upstream_art.secrets.len() - 1)
            .rev()
            .zip(update_context1.upstream_art.node_index.get_path().unwrap())
        {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }
    }

    /// the flow is as next:
    /// - Epoch1: remove some `target_user` with `user0`.
    /// - Epoch2: update key (`user0`), confirm remove (`user1`).
    /// - Epoch3: update key (`user0`, `user2`, `user3`).
    #[test]
    fn test_merge_flow_with_removal() {
        init_tracing();

        let mut rng = &mut StdRng::seed_from_u64(0);
        let secrets: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let creator_art = PrivateArt::setup(&secrets).unwrap();
        let public_art = creator_art.get_public_art().clone();

        // Create new users arts
        let mut user0 = PrivateZeroArt::new(creator_art, Box::new(thread_rng())).unwrap();

        let mut user1 = PrivateZeroArt::new(
            PrivateArt::new(public_art.clone(), secrets[1]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let mut user2 = PrivateZeroArt::new(
            PrivateArt::new(public_art.clone(), secrets[2]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let mut user3 = PrivateZeroArt::new(
            PrivateArt::new(public_art.clone(), secrets[8]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        let target_user = PrivateZeroArt::new(
            PrivateArt::new(public_art.clone(), secrets[5]).unwrap(),
            Box::new(thread_rng()),
        )
        .unwrap();

        // remove user
        let epoch1_removal = user0
            .remove_member(target_user.get_node_index(), Fr::rand(&mut rng))
            .unwrap();

        epoch1_removal.apply(&mut user0).unwrap();
        user0.commit().unwrap();

        epoch1_removal.apply(&mut user1).unwrap();
        user1.commit().unwrap();

        epoch1_removal.apply(&mut user2).unwrap();
        user2.commit().unwrap();

        epoch1_removal.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);

        // Remove the same user for second time
        let epoch2_removal = user1
            .remove_member(target_user.get_node_index(), Fr::rand(&mut rng))
            .unwrap();
        let epoch2_key_update = user0.update_key(Fr::rand(&mut rng)).unwrap();

        epoch2_key_update.apply(&mut user0).unwrap();
        epoch2_removal.apply(&mut user0).unwrap();
        user0.commit().unwrap();

        epoch2_removal.apply(&mut user1).unwrap();
        epoch2_key_update.apply(&mut user1).unwrap();
        user1.commit().unwrap();

        epoch2_removal.apply(&mut user2).unwrap();
        epoch2_key_update.apply(&mut user2).unwrap();
        user2.commit().unwrap();

        epoch2_key_update.apply(&mut user3).unwrap();
        epoch2_removal.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        let root = *epoch2_removal.branch_change.public_keys.first().unwrap()
            + *epoch2_key_update.branch_change.public_keys.first().unwrap();
        let root = root.into_affine();

        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);

        // Create some concurrent changes
        let sk0 = Fr::rand(&mut rng);
        let private_change0 = user0.update_key(sk0).unwrap();
        let change0 = private_change0.get_branch_change().clone();

        let sk2 = Fr::rand(&mut rng);
        let private_change2 = user2.update_key(sk2).unwrap();
        let change2 = private_change2.get_branch_change().clone();

        let sk3 = Fr::rand(&mut rng);
        let private_change3 = user3.update_key(sk3).unwrap();
        let change3 = private_change3.get_branch_change().clone();

        let new_root = *change0.public_keys.first().unwrap()
            + *change2.public_keys.first().unwrap()
            + *change3.public_keys.first().unwrap();
        let new_root = new_root.into_affine();

        // Apply changes to ART trees. Use private_change to apply change of the user own key.
        private_change0.apply(&mut user0).unwrap();
        change2.apply(&mut user0).unwrap();
        change3.apply(&mut user0).unwrap();
        user0.commit().unwrap();

        change0.apply(&mut user1).unwrap();
        change2.apply(&mut user1).unwrap();
        change3.apply(&mut user1).unwrap();
        user1.commit().unwrap();

        change0.apply(&mut user2).unwrap();
        private_change2.apply(&mut user2).unwrap();
        change3.apply(&mut user2).unwrap();
        user2.commit().unwrap();

        change0.apply(&mut user3).unwrap();
        change2.apply(&mut user3).unwrap();
        private_change3.apply(&mut user3).unwrap();
        user3.commit().unwrap();

        assert_eq!(user0.get_upstream_art().get_root_public_key(), new_root);
        assert_eq!(user1.get_upstream_art().get_root_public_key(), new_root);
        assert_eq!(user2.get_upstream_art().get_root_public_key(), new_root);
        assert_eq!(user3.get_upstream_art().get_root_public_key(), new_root);

        // Now all the participants have the same view on the state of the art
        assert_eq!(user0, user1);
        assert_eq!(user0, user2);
        assert_eq!(user0, user3);
    }
}
