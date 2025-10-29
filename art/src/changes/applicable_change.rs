use crate::TreeMethods;
use crate::art::art_node::LeafStatus;
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt, PublicZeroArt};
use crate::changes::aggregations::{PlainChangeAggregation, ProverChangeAggregation};
use crate::changes::branch_change::{
    BranchChange, BranchChangeType, MergeBranchChange,
};
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
    fn update(&self, art: &mut T) -> Result<(), ArtError>;
}

impl<G> ApplicableChange<PublicArt<G>> for BranchChange<G>
where
    G: AffineRepr,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
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
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
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
    fn update(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.update(&mut art.public_art)
    }
}


impl<'a, R> ApplicableChange<PrivateZeroArt<'a, R>> for BranchChange<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn update(&self, art: &mut PrivateZeroArt<'a, R>) -> Result<(), ArtError> {
        self.update(&mut art.private_art)
    }
}

impl<G> ApplicableChange<PublicArt<G>> for MergeBranchChange<PublicArt<G>, BranchChange<G>>
where
    G: AffineRepr,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
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
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
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

impl<G> ApplicableChange<PublicArt<G>> for PlainChangeAggregation<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        self.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for PlainChangeAggregation<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        self.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt> for PlainChangeAggregation<CortadoAffine> {
    fn update(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        self.update_public_art(&mut art.public_art)
    }
}

impl<'a, R> ApplicableChange<PrivateZeroArt<'a, R>> for PlainChangeAggregation<CortadoAffine>
where
    R: Rng + ?Sized,
{
    fn update(&self, art: &mut PrivateZeroArt<'a, R>) -> Result<(), ArtError> {
        self.update_private_art(&mut art.private_art)
    }
}

impl<G> ApplicableChange<PublicArt<G>> for ProverChangeAggregation<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let plain_aggregation = PlainChangeAggregation::try_from(self)?;
        plain_aggregation.update_public_art(art)
    }
}

impl<G> ApplicableChange<PrivateArt<G>> for ProverChangeAggregation<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn update(&self, art: &mut PrivateArt<G>) -> Result<(), ArtError> {
        let plain_aggregation = PlainChangeAggregation::try_from(self)?;
        plain_aggregation.update_private_art(art)
    }
}

impl ApplicableChange<PublicZeroArt> for ProverChangeAggregation<CortadoAffine> {
    fn update(&self, art: &mut PublicZeroArt) -> Result<(), ArtError> {
        let plain_aggregation = PlainChangeAggregation::try_from(self)?;
        plain_aggregation.update_public_art(&mut art.public_art)
    }
}

impl<'a, R> ApplicableChange<PrivateZeroArt<'a, R>> for ProverChangeAggregation<CortadoAffine>
where
    R: ?Sized + Rng,
{
    fn update(&self, art: &mut PrivateZeroArt<'a, R>) -> Result<(), ArtError> {
        let plain_aggregation = PlainChangeAggregation::try_from(self)?;
        plain_aggregation.update_private_art(&mut art.private_art)
    }
}

#[cfg(test)]
mod test {
    use crate::TreeMethods;
    use crate::art::ArtAdvancedOps;
    use crate::art::art_types::{PrivateArt, PublicArt};
    use crate::changes::applicable_change::ApplicableChange;
    use crate::changes::branch_change::MergeBranchChange;
    use crate::init_tracing;
    use crate::node_index::NodeIndex;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_std::UniformRand;
    use ark_std::rand::SeedableRng;
    use ark_std::rand::prelude::StdRng;
    use cortado::{CortadoAffine, Fr};
    use itertools::Itertools;
    use postcard::{from_bytes, to_allocvec};
    use std::ops::Mul;

    const DEFAULT_TEST_GROUP_SIZE: i32 = 100;

    #[test]
    fn test_changes_ordering_for_merge() {
        init_tracing();

        let seed = rand::random();
        let mut rng = &mut StdRng::seed_from_u64(seed);
        let secrets = (0..DEFAULT_TEST_GROUP_SIZE)
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
        let change3 = user3
            .remove_member(&target_node_index, sk3)
            .unwrap();

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

        let root_key_sk = user0.get_root_secret_key().unwrap()
            + user2.get_root_secret_key().unwrap()
            + user3.get_root_secret_key().unwrap()
            + user4.get_root_secret_key().unwrap()
            + user5.get_root_secret_key().unwrap();

        // Check correctness of the merge
        let mut art_def0 = user0.clone();
        let merge_change_but_0 = MergeBranchChange::new_for_participant(
            art0.clone(),
            applied_change.clone(),
            all_but_0_changes.clone(),
        );
        merge_change_but_0.update(&mut art_def0).unwrap();

        let mut art_def1 = art1.clone();
        let merge_all_change = MergeBranchChange::new_for_observer(all_changes.clone());
        merge_all_change.update(&mut art_def1).unwrap();
        // art_def1.merge_for_observer(&all_changes).unwrap();

        assert_eq!(
            art_def0.get_root(),
            art_def1.get_root(),
            "Observer and participant have the same view on the state of the art."
        );

        assert_eq!(
            art_def0.get_root_secret_key().ok(),
            art_def1.get_root_secret_key().ok(),
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
            merge_change_but_0.update(&mut art_0_analog).unwrap();

            assert_eq!(
                art_0_analog, art_def0,
                "The order of changes applied doesn't affect the result."
            );
        }

        for permutation in all_changes.iter().cloned().permutations(all_changes.len()) {
            let merge_all_change = MergeBranchChange::new_for_observer(permutation);

            let mut art_1_analog = art1.clone();
            merge_all_change.update(&mut art_1_analog).unwrap();

            assert_eq!(
                art_1_analog, art_def0,
                "The order of changes applied doesn't affect the result."
            );
        }
    }
}
