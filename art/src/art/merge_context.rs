use crate::TreeMethods;
use crate::art::art_node::{ArtNode, LeafStatus};
use crate::art::art_types::{PrivateArt, PublicArt};
use crate::art::{ArtBasicOps, ArtUpdateOutput};
use crate::changes::aggregations::AggregationNode;
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::errors::ArtError;
use crate::helper_tools::{default_proof_basis, default_verifier_engine, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;
use zrt_zk::engine::{ZeroArtEngineOptions, ZeroArtProverEngine, ZeroArtVerifierEngine};

pub struct PublicZeroArt<G>
where
    G: AffineRepr,
{
    pub(crate) base_art: PublicArt<G>,
    pub(crate) upstream_art: PublicArt<G>,
    pub(crate) marker_tree: AggregationNode<bool>,
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
            verifier_engine: default_verifier_engine(),
        })
    }

    pub fn commit(&mut self) {
        self.marker_tree.data = false;
        self.base_art = self.upstream_art.clone();
    }

    pub fn discard(&mut self) {
        self.marker_tree.data = false;
        self.upstream_art = self.base_art.clone();
    }
}

// TODO: Remove clone
#[derive(Clone)]
pub struct PrivateZeroArt<G, R>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
    R: Rng + ?Sized,
{
    pub(crate) base_art: PrivateArt<G>,
    pub(crate) upstream_art: PrivateArt<G>,
    pub(crate) marker_tree: AggregationNode<bool>,
    pub(crate) rng: Box<R>,
    pub(crate) prover_engine: Rc<ZeroArtProverEngine>,
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

    pub fn clone_without_rng(&self, rng: Box<R>) -> Self {
        Self {
            base_art: self.base_art.clone(),
            upstream_art: self.upstream_art.clone(),
            marker_tree: self.marker_tree.clone(),
            rng,
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

    pub fn get_node_index(&self) -> &NodeIndex {
        self.get_base_art().get_node_index()
    }

    pub fn commit(&mut self) {
        self.marker_tree.data = false;
        self.base_art = self.upstream_art.clone();
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
                vec![public_key.clone()]
            } else {
                // else it is or self update or AddMember, which is forbidden.
                vec![]
            };
        partial_co_path.append(&mut target_art.public_art.get_co_path_values(&intersection)?);

        // trace!("art: \n{}", self.get_upstream_art().get_root());

        // trace!(
        //     "public_key of level_sk: {}",
        //     G::generator().mul(target_art.secrets[target_art.secrets.len() - partial_co_path.len()]).into_affine(),
        // );
        let level_sk = target_art.secrets
            [(target_art.secrets.len() - partial_co_path.len()).saturating_sub(1)];

        let secrets = recompute_artefacts(level_sk, &partial_co_path)?.secrets;

        Ok(secrets[1..].to_vec())
    }

    pub(crate) fn update_secrets(
        &mut self,
        updated_secrets: &Vec<G::ScalarField>,
        merge_key: bool,
    ) -> Result<(), ArtError> {
        for (sk, i) in updated_secrets
            .iter()
            .rev()
            .zip((0..self.upstream_art.secrets.len()).rev())
        {
            if merge_key {
                self.upstream_art.secrets[i] += sk;
            } else {
                self.upstream_art.secrets[i] = *sk;
            }
        }

        Ok(())
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
) -> Result<(), ArtError>
where
    G: AffineRepr,
{
    // if true, then add member was with extension (instead of replacement).
    if upstream_art
        .node_index
        .is_subpath_of_vec(target_node_path)?
    {
        let secret = upstream_art
            .secrets
            .first()
            .ok_or(ArtError::EmptyArt)?
            .clone();

        upstream_art.secrets.insert(0, secret);
    }

    Ok(())
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
    let parent_art_node = upstream_art.get_mut_node_at(&target_node_path)?;

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
    let parent_marker_node = marker_tree.get_mut_node(&target_node_path)?;

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
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use itertools::Itertools;
    use postcard::{from_bytes, to_allocvec};
    use rand::random;
    use std::ops::{Add, Mul};

    const DEFAULT_TEST_GROUP_SIZE: i32 = 10;

    #[test]
    fn test_if_change_and_ephemeral_change_are_the_same() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..100).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let mut art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();
        let mut merge_context0 =
            PrivateZeroArt::new(art0.clone(), Box::new(StdRng::seed_from_u64(random()))).unwrap();

        let new_sk = Fr::rand(&mut rng);
        let change_a = art0.update_key(new_sk).unwrap();
        let change_b = merge_context0.update_key(new_sk).unwrap().branch_change;

        assert_eq!(
            change_a, change_b,
            "fail to assert_eq on tree1:\n{:#?}\n and merge context:\n{:#?}",
            change_a, change_b,
        );
    }

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
            merge_context0.commit();
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
        merge_context0.commit();

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
        merge_context0.commit();
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

    #[test]
    fn test_changes_ordering_for_merge() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..7).map(|_| Fr::rand(&mut rng)).collect::<Vec<_>>();

        let def_art: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

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

        let sk0 = Fr::rand(&mut rng);
        let private_change1 = user1.update_key(sk0).unwrap();
        let change1 = private_change1.branch_change.clone();

        let sk2 = Fr::rand(&mut rng);
        let change2 = user2.update_key(sk2).unwrap().branch_change;

        let sk3 = Fr::rand(&mut rng);
        let target_user_public_key = CortadoAffine::generator().mul(secrets[6]).into_affine();
        let target_node_index = NodeIndex::from(
            user3
                .base_art
                .get_path_to_leaf_with(target_user_public_key)
                .unwrap(),
        );
        let change3 = user3
            .remove_member(&target_node_index, sk3)
            .unwrap()
            .branch_change;

        let sk4 = Fr::rand(&mut rng);
        let change4 = user4.update_key(sk4).unwrap().branch_change;

        let sk5 = Fr::rand(&mut rng);
        let change5 = user5.update_key(sk5).unwrap().branch_change;

        let all_but_1_changes: Vec<BranchChange<CortadoAffine>> = vec![
            change2.clone(),
            change3.clone(),
            change4.clone(),
            change5.clone(),
        ];
        let all_changes = vec![
            change1.clone(),
            change2.clone(),
            change3.clone(),
            change4.clone(),
            change5.clone(),
        ];

        let root_key_sk = user1.upstream_art.get_root_secret_key()
            + user2.upstream_art.get_root_secret_key()
            + user3.upstream_art.get_root_secret_key()
            + user4.upstream_art.get_root_secret_key()
            + user5.upstream_art.get_root_secret_key();

        // Check correctness of the merge
        let mut user0_test_art = PrivateZeroArt::new(
            PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap(),
            Box::new(StdRng::seed_from_u64(random())),
        )
        .unwrap();
        for change in &all_changes {
            change.apply(&mut user0_test_art).unwrap();
        }
        user0_test_art.commit();

        let mut user1_test_art = user1.clone();
        private_change1.apply(&mut user1_test_art).unwrap();
        for change in &all_but_1_changes {
            change.apply(&mut user1_test_art).unwrap()
        }
        user1_test_art.commit();

        assert_eq!(
            user0_test_art.marker_tree, user1_test_art.marker_tree,
            "Observer and participant have the same view on the state of the art.\
            User0 is:\n{}\nuser1 is:\n{}",
            user0_test_art.marker_tree, user1_test_art.marker_tree,
        );

        assert_eq!(
            user0_test_art.upstream_art,
            user1_test_art.upstream_art,
            "Observer and participant have the same view on the state of the art.\
            User0 is:\n{}\nuser1 is:\n{}",
            user0_test_art.upstream_art.get_root(),
            user1_test_art.upstream_art.get_root(),
        );

        assert_eq!(
            user1_test_art.upstream_art, user0_test_art.upstream_art,
            "Observer and participant have the same view on the state of the art."
        );

        for permutation in all_but_1_changes
            .iter()
            .cloned()
            .permutations(all_but_1_changes.len())
        {
            let mut art_0_analog = user1.clone();
            private_change1.apply(&mut art_0_analog).unwrap();
            for change in &permutation {
                change.apply(&mut art_0_analog).unwrap()
            }
            art_0_analog.commit();

            assert_eq!(
                art_0_analog.upstream_art.get_root(),
                user0_test_art.upstream_art.get_root(),
                "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
                art_0_analog.upstream_art.get_root(),
                user0_test_art.upstream_art.get_root(),
            );
        }

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let mut art_1_analog = PrivateZeroArt::new(
                PrivateArt::new(def_art.public_art.clone(), secrets[0]).unwrap(),
                Box::new(StdRng::seed_from_u64(random())),
            )
            .unwrap();
            for change in permutation {
                change.apply(&mut art_1_analog).unwrap();
            }
            art_1_analog.commit();

            assert_eq!(
                art_1_analog.upstream_art.get_root(),
                user1_test_art.upstream_art.get_root(),
                "Observer and participant have the same view on the state of the art.\
                User0 is:\n{}\nUser1 is:\n{}",
                art_1_analog.upstream_art.get_root(),
                user1_test_art.upstream_art.get_root(),
            );
        }
    }

    // #[test]
    // fn test_merge_for_key_update() {
    //     init_tracing();
    //
    //     if DEFAULT_TEST_GROUP_SIZE < 5 {
    //         warn!("Cant run the test test_merge_for_add_member, as group size is to small");
    //         return;
    //     }
    //
    //     let mut rng = StdRng::from_seed(rand::random());
    //     let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
    //         .map(|_| Fr::rand(&mut rng))
    //         .collect::<Vec<_>>();
    //     let art = PrivateArt::<CortadoAffine>::setup(&secrets).unwrap();
    //
    //     let mut user_arts = Vec::new();
    //     for i in 0..DEFAULT_TEST_GROUP_SIZE {
    //         let art = PrivateArt::<CortadoAffine>::new(art.public_art.clone(), secrets[i]).unwrap();
    //         user_arts.push(art);
    //     }
    //
    //     let mut art1 = user_arts.remove(0);
    //     let mut art2 = user_arts.remove(1);
    //     let mut art3 = user_arts.remove(3);
    //     let mut art4 = user_arts.remove(4);
    //
    //     let def_art1 = art1.clone();
    //     let def_art2 = art2.clone();
    //     let def_art3 = art3.clone();
    //     let def_art4 = art4.clone();
    //
    //     assert_eq!(art1.get_root(), art2.get_root());
    //     assert_eq!(art1.get_root(), art3.get_root());
    //     assert_eq!(art1.get_root(), art4.get_root());
    //
    //     let new_node1_sk = Fr::rand(&mut rng);
    //     let new_node2_sk = Fr::rand(&mut rng);
    //     let new_node3_sk = Fr::rand(&mut rng);
    //     let new_node4_sk = Fr::rand(&mut rng);
    //
    //     let changes1 = art1.update_key(new_node1_sk).unwrap();
    //     let changes2 = art2.update_key(new_node2_sk).unwrap();
    //     let changes3 = art3.update_key(new_node3_sk).unwrap();
    //     let changes4 = art4.update_key(new_node4_sk).unwrap();
    //
    //     let tk1 = art1.get_root_secret_key();
    //     let tk2 = art2.get_root_secret_key();
    //     let tk3 = art3.get_root_secret_key();
    //     let tk4 = art4.get_root_secret_key();
    //
    //     let merged_tk = tk1 + tk2 + tk3 + tk4;
    //
    //     assert_eq!(
    //         art1.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(tk1).into_affine()
    //     );
    //     assert_eq!(
    //         art2.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(tk2).into_affine()
    //     );
    //     assert_eq!(
    //         art3.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(tk3).into_affine()
    //     );
    //     assert_eq!(
    //         art4.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(tk4).into_affine()
    //     );
    //
    //     assert_eq!(
    //         art1.get_root().get_public_key(),
    //         *changes1.public_keys.get(0).unwrap()
    //     );
    //     assert_eq!(
    //         art2.get_root().get_public_key(),
    //         *changes2.public_keys.get(0).unwrap()
    //     );
    //     assert_eq!(
    //         art3.get_root().get_public_key(),
    //         *changes3.public_keys.get(0).unwrap()
    //     );
    //     assert_eq!(
    //         art4.get_root().get_public_key(),
    //         *changes4.public_keys.get(0).unwrap()
    //     );
    //
    //     art1.merge_for_participant(
    //         changes1.clone(),
    //         &vec![changes2.clone(), changes3.clone(), changes4.clone()],
    //         def_art1.clone(),
    //     )
    //         .unwrap();
    //
    //     assert_eq!(
    //         art1.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(merged_tk).into_affine()
    //     );
    //     assert_eq!(merged_tk, art1.get_root_secret_key());
    //     let tk1_merged = art1.get_root_secret_key();
    //     assert_eq!(
    //         art1.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(tk1_merged).into_affine()
    //     );
    //
    //     art2.merge_for_participant(
    //         changes2.clone(),
    //         &vec![changes1.clone(), changes3.clone(), changes4.clone()],
    //         def_art2.clone(),
    //     )
    //         .unwrap();
    //
    //     assert_eq!(
    //         art2.get_root().get_public_key(),
    //         CortadoAffine::generator().mul(merged_tk).into_affine()
    //     );
    //     assert_eq!(merged_tk, art2.get_root_secret_key());
    //
    //     let mut root_key_from_changes = CortadoAffine::zero();
    //     for g in &vec![
    //         changes1.clone(),
    //         changes2.clone(),
    //         changes3.clone(),
    //         changes4.clone(),
    //     ] {
    //         root_key_from_changes = root_key_from_changes.add(g.public_keys[0]).into_affine();
    //     }
    //     assert_eq!(
    //         root_key_from_changes,
    //         CortadoAffine::generator().mul(merged_tk).into_affine()
    //     );
    //     assert_eq!(root_key_from_changes, art1.get_root().get_public_key());
    //     assert_eq!(
    //         art1.get_root().get_public_key(),
    //         CortadoAffine::generator()
    //             .mul(art1.get_root_secret_key())
    //             .into_affine(),
    //     );
    //
    //     assert_eq!(
    //         CortadoAffine::generator().mul(new_node1_sk).into_affine(),
    //         art1.get_public_art()
    //             .get_node(&art1.get_node_index())
    //             .unwrap()
    //             .get_public_key()
    //     );
    //     assert_eq!(
    //         CortadoAffine::generator().mul(new_node2_sk).into_affine(),
    //         art2.get_public_art()
    //             .get_node(&art2.get_node_index())
    //             .unwrap()
    //             .get_public_key()
    //     );
    //
    //     assert_eq!(art1, art2);
    //
    //     let all_changes = vec![changes1, changes2, changes3, changes4];
    //     let observer_merge_change = MergeBranchChange::new_for_observer(all_changes.clone());
    //     for i in 0..DEFAULT_TEST_GROUP_SIZE - 4 {
    //         observer_merge_change.apply(&mut user_arts[i]).unwrap();
    //
    //         let tk = user_arts[i].get_root_secret_key();
    //
    //         assert_eq!(
    //             root_key_from_changes,
    //             user_arts[i].get_root().get_public_key()
    //         );
    //         assert_eq!(
    //             user_arts[i].get_root().get_public_key(),
    //             CortadoAffine::generator().mul(tk).into_affine(),
    //         );
    //         assert_eq!(merged_tk, user_arts[i].get_root_secret_key());
    //     }
    //
    //     let post_merge_sk = Fr::rand(&mut rng);
    //     let post_change = art1.update_key(post_merge_sk).unwrap();
    //
    //     post_change.apply(&mut art2).unwrap();
    //
    //     assert_eq!(art1, art2);
    //
    //     for i in 0..DEFAULT_TEST_GROUP_SIZE - 4 {
    //         post_change.apply(&mut user_arts[i]).unwrap();
    //         assert_eq!(art1, art2);
    //     }
    // }

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
}
