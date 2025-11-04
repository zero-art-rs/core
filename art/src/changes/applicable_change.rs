use crate::TreeMethods;
use crate::art::art_node::LeafStatus;
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::changes::aggregations::{AggregatedChange, AggregationContext};
use crate::changes::branch_change::{BranchChange, BranchChangeType, MergeBranchChange};
use crate::errors::ArtError;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::CortadoAffine;
use std::mem;

/// A trait for ART change that can be applied to the ART.
///
/// This trait represents an ability of change to update some instance of ART of type `T`.
///
/// # Type Parameters
/// * `T` – The type of the ART tree type being updated.
pub trait ApplicableChange<T> {
    fn apply(&self, art: &mut T) -> Result<(), ArtError>;
}

impl<G> ApplicableChange<PublicArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && let Some(LeafStatus::Blank) = art.get_node(&self.node_index)?.get_status()
        {
            art.update_with_options(self, true, false)
        } else {
            art.update_with_options(self, false, true)
        }
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for BranchChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        if let BranchChangeType::RemoveMember = self.change_type
            && matches!(
                art.public_art.get_node(&self.node_index)?.get_status(),
                Some(LeafStatus::Blank)
            )
        {
            art.update_private_art_with_options(self, true, false)
        } else {
            art.update_private_art_with_options(self, false, true)
        }
    }
}

impl ApplicableChange<PublicZeroArt> for BranchChange<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.apply(&mut art.public_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        self.apply(&mut art.private_art)
    }
}

impl<G> ApplicableChange<PublicArt<G>> for MergeBranchChange<PublicArt<G>, BranchChange<G>>
where
    G: AffineRepr,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        if let Some((base_fork, change)) = &self.applied_helper_data {
            _ = mem::replace(art, base_fork.clone());
            let changes = [vec![change.clone()], self.unapplied_changes.clone()]
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            art.merge_all(&changes)?;
        } else {
            art.merge_all(&self.unapplied_changes)?;
        }

        Ok(())
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for MergeBranchChange<PrivateArt<G>, BranchChange<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        if let Some((base_fork, applied_change)) = &self.applied_helper_data {
            art.merge_for_participant(
                applied_change.clone(),
                &self.unapplied_changes,
                base_fork.clone(),
            )
        } else {
            art.merge_for_observer(&self.unapplied_changes)
        }
    }
}

impl ApplicableChange<PublicZeroArt>
    for MergeBranchChange<PublicArt<CortadoAffine>, BranchChange<CortadoAffine>>
{
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        if let Some((base_fork, change)) = &self.applied_helper_data {
            _ = mem::replace(&mut art.public_art, base_fork.clone());
            let changes = [vec![change.clone()], self.unapplied_changes.clone()]
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            art.public_art.merge_all(&changes)?;
        } else {
            art.public_art.merge_all(&self.unapplied_changes)?;
        }

        Ok(())
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>>
    for MergeBranchChange<PrivateArt<CortadoAffine>, BranchChange<CortadoAffine>>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        if let Some((base_fork, applied_change)) = &self.applied_helper_data {
            art.private_art.merge_for_participant(
                applied_change.clone(),
                &self.unapplied_changes,
                base_fork.clone(),
            )
        } else {
            art.private_art.merge_for_observer(&self.unapplied_changes)
        }
    }
}

impl ApplicableChange<PublicZeroArt>
for MergeBranchChange<PublicZeroArt, BranchChange<CortadoAffine>>
{
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        if let Some((base_fork, change)) = &self.applied_helper_data {
            _ = mem::replace(&mut art.public_art, base_fork.public_art.clone());
            let changes = [vec![change.clone()], self.unapplied_changes.clone()]
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            art.public_art.merge_all(&changes)?;
        } else {
            art.public_art.merge_all(&self.unapplied_changes)?;
        }

        Ok(())
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>>
for MergeBranchChange<PrivateZeroArt<R>, BranchChange<CortadoAffine>>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        if let Some((base_fork, applied_change)) = &self.applied_helper_data {
            art.private_art.merge_for_participant(
                applied_change.clone(),
                &self.unapplied_changes,
                base_fork.private_art.clone(),
            )
        } else {
            art.private_art.merge_for_observer(&self.unapplied_changes)
        }
    }
}

impl<G> ApplicableChange<PublicArt<G>> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        self.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        self.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt> for AggregatedChange<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.update_public_art(&mut art.public_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>> for AggregatedChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        self.update_private_art(&mut art.private_art)
    }
}

impl<G> ApplicableChange<PublicArt<G>> for AggregationContext<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(self)?;
        plain_aggregation.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for AggregationContext<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(self)?;
        plain_aggregation.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt> for AggregationContext<CortadoAffine> {
    fn apply(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(self)?;
        plain_aggregation.update_public_art(&mut art.public_art)
    }
}

impl<R> ApplicableChange<PrivateZeroArt<R>> for AggregationContext<CortadoAffine>
where
    R: ?Sized + Rng,
{
    fn apply(&self, art: &mut PrivateZeroArt<R>) -> Result<(), ArtError> {
        let plain_aggregation = AggregatedChange::try_from(self)?;
        plain_aggregation.update_private_art(&mut art.private_art)
    }
}

#[cfg(test)]
mod test {
    use crate::TreeMethods;
    use crate::art::{ArtAdvancedOps, PrivateMergeContext, PublicMergeContext};
    use crate::art::art_types::{PrivateArt, PublicArt};
    use crate::changes::applicable_change::ApplicableChange;
    use crate::changes::branch_change::MergeBranchChange;
    use crate::init_tracing;
    use crate::node_index::{Direction, NodeIndex};
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use itertools::Itertools;
    use postcard::{from_bytes, to_allocvec};
    use std::ops::{Add, Mul};
    use tracing::{debug, info};

    const DEFAULT_TEST_GROUP_SIZE: i32 = 10;

    #[test]
    fn test_changes_ordering_for_merge() {
        init_tracing();

        let seed = 0;
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..100)
            .map(|_| Fr::rand(&mut rng))
            .collect::<Vec<_>>();

        let art0: PrivateArt<CortadoAffine> = PrivateArt::setup(&secrets).unwrap();

        // Serialise and deserialize art for the new user.
        let public_art_bytes = to_allocvec(&art0.get_public_art()).unwrap();
        let public_art: PublicArt<CortadoAffine> = from_bytes(&public_art_bytes).unwrap();

        let mut user0: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[0]).unwrap();

        let art1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

        let mut user2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[2]).unwrap();

        let mut user3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[8]).unwrap();

        let mut user4: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[10]).unwrap();

        let mut user5: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[67]).unwrap();

        let sk0 = Fr::rand(&mut rng);
        let change0 = user0.update_key(sk0).unwrap();

        let sk2 = Fr::rand(&mut rng);
        let change2 = user2.update_key(sk2).unwrap();

        let sk3 = Fr::rand(&mut rng);
        let target_user_public_key = CortadoAffine::generator().mul(secrets[25]).into_affine();
        let target_node_index =
            NodeIndex::from(user3.get_path_to_leaf_with(target_user_public_key).unwrap());
        let change3 = user3.remove_member(&target_node_index, sk3).unwrap();

        let sk4 = Fr::rand(&mut rng);
        let change4 = user4.update_key(sk4).unwrap();

        let sk5 = Fr::rand(&mut rng);
        let change5 = user5.update_key(sk5).unwrap();

        let applied_change = change0.clone();
        let all_but_0_changes = vec![
            change2.clone(),
            change3.clone(),
            change4.clone(),
            change5.clone(),
        ];
        let all_changes = vec![change0, change2, change3, change4, change5];

        let root_key_sk = user0.get_root_secret_key()
            + user2.get_root_secret_key()
            + user3.get_root_secret_key()
            + user4.get_root_secret_key()
            + user5.get_root_secret_key();

        // Check correctness of the merge
        let mut art_def0 = user0.clone();
        let merge_change_but_0 = MergeBranchChange::new_for_participant(
            art0.clone(),
            applied_change.clone(),
            all_but_0_changes.clone(),
        );
        merge_change_but_0.apply(&mut art_def0).unwrap();

        let mut art_def1 = art1.clone();
        let merge_all_change = MergeBranchChange::new_for_observer(all_changes.clone());
        merge_all_change.apply(&mut art_def1).unwrap();
        // art_def1.merge_for_observer(&all_changes).unwrap();

        assert_eq!(
            art_def0.get_root(),
            art_def1.get_root(),
            "Observer and participant have the same view on the state of the art."
        );

        assert_eq!(
            art_def0.get_root_secret_key(),
            art_def1.get_root_secret_key(),
            "Observer and participant have the same view on the state of the art."
        );

        assert_eq!(
            art_def0, art_def1,
            "Observer and participant have the same view on the state of the art."
        );

        for permutation in all_but_0_changes
            .iter()
            .cloned()
            .permutations(all_but_0_changes.len())
        {
            let merge_change_but_0 = MergeBranchChange::new_for_participant(
                art0.clone(),
                applied_change.clone(),
                permutation,
            );

            let mut art_0_analog = user0.clone();
            merge_change_but_0.apply(&mut art_0_analog).unwrap();

            assert_eq!(
                art_0_analog, art_def0,
                "The order of changes applied doesn't affect the result."
            );
        }

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let merge_all_change = MergeBranchChange::new_for_observer(permutation);

            let mut art_1_analog = art1.clone();
            merge_all_change.apply(&mut art_1_analog).unwrap();

            assert_eq!(
                art_1_analog, art_def0,
                "The order of changes applied doesn't affect the result."
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
        let mut update_context1 = PrivateMergeContext::new(art0.clone());

        let mut art0: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[0]).unwrap();

        let mut art1: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[1]).unwrap();

        let mut art2: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[2]).unwrap();

        let art3: PrivateArt<CortadoAffine> =
            PrivateArt::new(public_art.clone(), secrets[8]).unwrap();

        let mut update_context3 = PrivateMergeContext::new(art3);

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
            CortadoAffine::generator().mul(
                update_context1.upstream_art.secrets.last().unwrap().clone()
            ).into_affine(),
        );
        for (sk, dir) in update_context1.upstream_art.secrets.iter().take(update_context1.upstream_art.secrets.len() - 1).rev().zip(update_context1.upstream_art.node_index.get_path().unwrap()) {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }

        change2.apply(&mut update_context1).unwrap();

        change2.apply(&mut update_context3).unwrap();
        change1.apply(&mut update_context3).unwrap();
        assert_eq!(
            update_context1.upstream_art,
            update_context3.upstream_art,
        );
        assert_eq!(
            update_context1.base_art,
            update_context3.base_art,
        );

        let mut parent = update_context1.upstream_art.get_root();
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator().mul(
                update_context1.upstream_art.secrets.last().unwrap().clone()
            ).into_affine(),
        );
        for (sk, dir) in update_context1.upstream_art.secrets.iter().take(update_context1.upstream_art.secrets.len() - 1).rev().zip(update_context1.upstream_art.node_index.get_path().unwrap()) {
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
                CortadoAffine::generator().mul(update_context1.upstream_art.secrets[i]).into_affine(),
                CortadoAffine::generator().mul(art1.secrets[i] + art2.secrets[i]).into_affine(),
            );

            assert_eq!(
                update_context1.upstream_art.secrets[i],
                art1.secrets[i] + art2.secrets[i],
            );
        }

        assert_eq!(
            update_context1.upstream_art.get_root().get_public_key(),
            art1.get_root().get_public_key().add(art2.get_root().get_public_key()).into_affine(),
        );

        let path2 = [Direction::Left];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path2).unwrap().get_public_key(),
            art1.get_node_at(&path2).unwrap().get_public_key().add(
                art2.get_node_at(&path2).unwrap().get_public_key()
            ).into_affine(),
        );

        let path3 = [Direction::Right];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path3).unwrap().get_public_key(),
            art1.get_node_at(&path3).unwrap().get_public_key()
        );
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path3).unwrap().get_public_key(),
            art2.get_node_at(&path3).unwrap().get_public_key()
        );

        let path4 = [Direction::Left, Direction::Left];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path4).unwrap().get_public_key(),
            art1.get_node_at(&path4).unwrap().get_public_key().add(
                art2.get_node_at(&path4).unwrap().get_public_key()
            ).into_affine(),
        );

        let path8 = [Direction::Left, Direction::Left, Direction::Left];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path8).unwrap().get_public_key(),
            art1.get_node_at(&path8).unwrap().get_public_key(),
        );

        let path9 = [Direction::Left, Direction::Left, Direction::Right];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path9).unwrap().get_public_key(),
            art2.get_node_at(&path9).unwrap().get_public_key(),
        );

        let path16 = [Direction::Left, Direction::Left, Direction::Left, Direction::Left];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path16).unwrap().get_public_key(),
            art1.get_node_at(&path16).unwrap().get_public_key(),
        );
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path16).unwrap().get_public_key(),
            art2.get_node_at(&path16).unwrap().get_public_key(),
        );

        let path17 = [Direction::Left, Direction::Left, Direction::Left, Direction::Right];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path17).unwrap().get_public_key(),
            art1.get_node_at(&path17).unwrap().get_public_key(),
        );
        assert_ne!(
            update_context1.upstream_art.get_node_at(&path17).unwrap().get_public_key(),
            art2.get_node_at(&path17).unwrap().get_public_key(),
        );

        let path18 = [Direction::Left, Direction::Left, Direction::Right, Direction::Left];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path18).unwrap().get_public_key(),
            art2.get_node_at(&path18).unwrap().get_public_key(),
        );
        assert_ne!(
            update_context1.upstream_art.get_node_at(&path18).unwrap().get_public_key(),
            art1.get_node_at(&path18).unwrap().get_public_key(),
        );

        let path19 = [Direction::Left, Direction::Left, Direction::Right, Direction::Right];
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path19).unwrap().get_public_key(),
            art2.get_node_at(&path19).unwrap().get_public_key(),
        );
        assert_eq!(
            update_context1.upstream_art.get_node_at(&path19).unwrap().get_public_key(),
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
            CortadoAffine::generator().mul(
                update_context1.upstream_art.secrets.last().unwrap().clone()
            ).into_affine(),
        );
        for (sk, dir) in update_context1.upstream_art.secrets.iter().take(update_context1.upstream_art.secrets.len() - 1).rev().zip(update_context1.upstream_art.node_index.get_path().unwrap()) {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }

        change.apply(&mut update_context1).unwrap();

        // debug!("update_context:\n{}", update_context1.upstream_art.get_root());

        let mut root = update_context1.upstream_art.get_root();
        assert_eq!(root.get_public_key(), change.public_keys.first().unwrap().clone());
        for (dir, pk) in change.node_index.get_path().unwrap().iter().zip(&change.public_keys[1..]) {
            root = root.get_child(*dir).unwrap();

            assert_eq!(root.get_public_key(), *pk);
        }

        let mut parent = update_context1.upstream_art.get_root();
        assert_eq!(
            parent.get_public_key(),
            CortadoAffine::generator().mul(
                update_context1.upstream_art.secrets.last().unwrap().clone()
            ).into_affine(),
        );
        for (sk, dir) in update_context1.upstream_art.secrets.iter().take(update_context1.upstream_art.secrets.len() - 1).rev().zip(update_context1.upstream_art.node_index.get_path().unwrap()) {
            parent = parent.get_child(dir).unwrap();
            assert_eq!(
                parent.get_public_key(),
                CortadoAffine::generator().mul(sk).into_affine(),
            );
        }
    }
}
