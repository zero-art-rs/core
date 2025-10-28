use crate::art::ArtUpdateOutput;
use crate::art::art_node::{ArtNode, LeafStatus};
use crate::art::art_types::{PrivateArt, PrivateZeroArt, PublicArt};
use crate::art::artefacts::ProverArtefacts;
use crate::changes::aggregations::{
    AggregationData, AggregationNode, AggregationNodeIterWithPath, ProverAggregationData,
    RelatedData, VerifierAggregationData,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType, BranchChangesTypeHint};
use crate::errors::ARTError;
use crate::helper_tools::recompute_artefacts;
use crate::node_index::{Direction, NodeIndex};
use crate::tree_methods::TreeMethods;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use cortado::{CortadoAffine, Fr};
use std::fmt::{Display, Formatter};
use std::ops::Mul;
use zrt_zk::EligibilityArtefact;
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};
use zrt_zk::art::ArtProof;

pub type ProverChangeAggregation<G> = ChangeAggregation<ProverAggregationData<G>>;
pub type PlainChangeAggregation<G> = ChangeAggregation<AggregationData<G>>;
pub(crate) type VerifierChangeAggregation<G> = ChangeAggregation<VerifierAggregationData<G>>;

pub type PlainChangeAggregationWithProof<G> = (ChangeAggregation<AggregationData<G>>, ArtProof);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub(crate) root: Option<AggregationNode<D>>,
}

impl<D> ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub fn get_root(&self) -> Option<&AggregationNode<D>> {
        self.root.as_ref()
    }
}

impl<G> ChangeAggregation<AggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    /// Update public art public keys with ones provided in the `verifier_aggregation` tree.
    pub fn add_co_path(
        &self,
        art: &PublicArt<G>,
    ) -> Result<VerifierChangeAggregation<G>, ARTError> {
        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        let mut resulting_aggregation_root =
            AggregationNode::<VerifierAggregationData<G>>::try_from(agg_root)?;

        for (_, path) in AggregationNodeIterWithPath::new(agg_root).skip(1) {
            let mut parent_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let last_direction = parent_path.pop().ok_or(ARTError::NoChanges)?;

            let aggregation_parent = path
                .last()
                .ok_or(ARTError::NoChanges)
                .map(|(node, _)| *node)?;

            let resulting_target_node = resulting_aggregation_root
                .get_mut_node(&parent_path)?
                .get_mut_node(&[last_direction])?;

            // Update co-path
            let pk = if let Ok(co_leaf) = aggregation_parent.get_node(&[last_direction.other()]) {
                // Retrieve co-path from the aggregation
                co_leaf.data.public_key
            } else if let Ok(parent) = art.get_node(&NodeIndex::Direction(parent_path.clone()))
                && let Some(other_child) = parent.get_child(last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                other_child.get_public_key()
            } else {
                // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                Self::get_last_public_key_on_path(art, agg_root, &path)?
            };
            resulting_target_node.data.co_public_key = Some(pk);
        }

        Ok(ChangeAggregation {
            root: Some(resulting_aggregation_root),
        })
    }

    /// Retrieve the last public key on given `path`, by applying required changes from the
    /// `aggregation`.
    pub(crate) fn get_last_public_key_on_path(
        art: &PublicArt<G>,
        aggregation: &AggregationNode<AggregationData<G>>,
        path: &[Direction],
    ) -> Result<G, ARTError> {
        let mut leaf_public_key = art.get_root().get_public_key();

        let mut current_art_node = Some(art.get_root());
        let mut current_agg_node = Some(aggregation);
        for (i, dir) in path.iter().enumerate() {
            // Retrieve leaf public key from art
            if let Some(art_node) = current_art_node {
                if let Some(node) = art_node.get_child(*dir) {
                    if let ArtNode::Leaf { public_key, .. } = node {
                        leaf_public_key = *public_key;
                    }

                    current_art_node = Some(node);
                } else {
                    current_art_node = None;
                }
            }

            // Retrieve leaf public key updates form aggregation
            if let Some(agg_node) = current_agg_node {
                if let Some(node) = agg_node.get_child(*dir) {
                    for change_type in &node.data.change_type {
                        match change_type {
                            BranchChangesTypeHint::RemoveMember { pk: blank_pk, .. } => {
                                leaf_public_key = *blank_pk
                            }
                            BranchChangesTypeHint::AddMember { pk, ext_pk, .. } => {
                                if let Some(replacement_pk) = ext_pk {
                                    match path.get(i + 1) {
                                        Some(Direction::Right) => leaf_public_key = *pk,
                                        Some(Direction::Left) => {}
                                        None => leaf_public_key = *replacement_pk,
                                    }
                                } else {
                                    leaf_public_key = *pk;
                                }
                            }
                            BranchChangesTypeHint::UpdateKey { pk } => leaf_public_key = *pk,
                            BranchChangesTypeHint::Leave { pk } => leaf_public_key = *pk,
                        }
                    }

                    current_agg_node = Some(node);
                } else {
                    current_agg_node = None;
                }
            }
        }

        Ok(leaf_public_key)
    }
}

// impl<G> ChangeAggregation<VerifierAggregationData<G>>
impl<G> ChangeAggregation<AggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub(crate) fn update_public_art(&self, art: &mut PublicArt<G>) -> Result<(), ARTError> {
        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        for (item, path) in AggregationNodeIterWithPath::new(agg_root) {
            let item_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            for change_type in &item.data.change_type {
                match change_type {
                    BranchChangesTypeHint::RemoveMember {
                        pk: blank_pk,
                        merge,
                    } => {
                        if !*merge {
                            art.update_branch_weight(&item_path, false)?;
                        }

                        self.update_public_art_upper_branch(&item_path, art, false, 0)?;

                        let corresponding_item =
                            art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.set_status(LeafStatus::Blank)?;
                        corresponding_item.set_public_key(*blank_pk);
                    }
                    BranchChangesTypeHint::AddMember { pk, ext_pk } => {
                        art.update_branch_weight(&item_path, true)?;

                        art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?
                            .extend_or_replace(ArtNode::new_leaf(*pk))?;

                        let mut parent_path = item_path.clone();
                        parent_path.pop();
                        self.update_public_art_upper_branch(&parent_path, art, false, 0)?;

                        let corresponding_item =
                            art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        if let Some(ext_pk) = ext_pk {
                            corresponding_item.set_public_key(*ext_pk)
                        }
                    }
                    BranchChangesTypeHint::UpdateKey { pk } => {
                        self.update_public_art_upper_branch(&item_path, art, false, 0)?;

                        let corresponding_item =
                            art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.set_public_key(*pk);
                    }
                    BranchChangesTypeHint::Leave { pk } => {
                        self.update_public_art_upper_branch(&item_path, art, false, 0)?;

                        let corresponding_item =
                            art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?;
                        corresponding_item.set_status(LeafStatus::PendingRemoval)?;
                        corresponding_item.set_public_key(*pk);
                    }
                }
            }
        }

        Ok(())
    }

    /// Update art by applying changes from the provided aggregation. Also updates `path_secrets`
    /// and `node_index`.
    pub(crate) fn update_private_art(&self, art: &mut PrivateArt<G>) -> Result<(), ARTError> {
        self.update_public_art(&mut art.public_art)?;

        art.update_node_index()?;
        self.update_path_secrets_with_aggregation_tree(art)?;

        Ok(())
    }

    /// Allows to update public keys on the given `path` with public keys provided in
    /// `verifier_aggregation`. Also, it allows to skip and not update first `skip` nodes on path.
    fn update_public_art_upper_branch(
        &self,
        path: &[Direction],
        art: &mut PublicArt<G>,
        append_changes: bool,
        skip: usize,
    ) -> Result<(), ARTError> {
        let mut current_agg_node = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        // Update root
        if skip == 0 {
            match append_changes {
                true => art
                    .get_mut_root()
                    .merge_public_key(current_agg_node.data.public_key),
                false => art
                    .get_mut_root()
                    .set_public_key(current_agg_node.data.public_key),
            }
        }

        for i in 1..skip {
            current_agg_node = current_agg_node
                .get_child(path[i])
                .ok_or(ARTError::InvalidAggregation)?;
        }

        for i in skip..path.len() {
            current_agg_node = current_agg_node
                .get_child(path[i + skip])
                .ok_or(ARTError::InvalidAggregation)?;
            let target_node = art.get_mut_node_at(&path[0..i + 1])?;

            match append_changes {
                true => target_node.merge_public_key(current_agg_node.data.public_key),
                false => target_node.set_public_key(current_agg_node.data.public_key),
            }
        }

        Ok(())
    }

    /// Similar to `update_path_secrets`, but instead of NodeIndex `other` provided by change,
    /// takes the ChangeAggregation tree.
    fn update_path_secrets_with_aggregation_tree(
        &self,
        art: &mut PrivateArt<G>,
    ) -> Result<(), ARTError> {
        let path_secrets = art.secrets.clone();

        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if agg_root.contains(&art.get_node_index().get_path()?) {
            return Err(ARTError::InvalidInput);
        }

        // It is a partial update of the path.
        let node_path = art.get_node_index().get_path()?;
        let mut intersection = agg_root.get_intersection(&node_path);

        let mut partial_co_path = Vec::new();
        let mut current_art_node = art.get_root();
        let mut current_agg_node = agg_root;
        let mut add_member_counter = current_agg_node
            .data
            .change_type
            .iter()
            .filter(|change| matches!(change, BranchChangesTypeHint::AddMember { .. }))
            .count();
        for dir in &intersection {
            partial_co_path.push(
                current_art_node
                    .get_child(dir.other())
                    .ok_or(ARTError::InvalidInput)?
                    .get_public_key(),
            );

            current_art_node = current_art_node
                .get_child(*dir)
                .ok_or(ARTError::InvalidInput)?;
            current_agg_node = current_agg_node
                .get_child(*dir)
                .ok_or(ARTError::PathNotExists)?;

            add_member_counter += current_agg_node
                .data
                .change_type
                .iter()
                .filter(|change| matches!(change, BranchChangesTypeHint::AddMember { .. }))
                .count();
        }

        intersection.push(node_path[intersection.len()].other());
        partial_co_path.push(agg_root.get_node(&intersection)?.data.public_key);
        partial_co_path.reverse();

        // Compute path_secrets for aggregation.
        let resulting_path_secrets_len = art.secrets.len() + add_member_counter;
        let index = resulting_path_secrets_len - partial_co_path.len() - 1;
        let level_sk = art.secrets[index];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, &partial_co_path)?;

        let mut new_path_secrets = art.secrets.clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        // Update node `path_secrets`
        art.secrets = new_path_secrets;

        Ok(())
    }
}

impl<'a, D1, D2> TryFrom<&'a ChangeAggregation<D1>> for ChangeAggregation<D2>
where
    D1: RelatedData + Clone + Default,
    D2: From<D1> + RelatedData + Clone + Default,
    AggregationNode<D2>: TryFrom<&'a AggregationNode<D1>, Error = ARTError>,
{
    type Error = ARTError;

    fn try_from(value: &'a ChangeAggregation<D1>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(ChangeAggregation::default()),
            Some(root) => Ok(ChangeAggregation {
                root: Some(AggregationNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D, G> TryFrom<&'a ChangeAggregation<D>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
    D: RelatedData + Clone + Default,
    Self: TryFrom<&'a AggregationNode<D>, Error = ARTError>,
{
    type Error = <Self as TryFrom<&'a AggregationNode<D>>>::Error;

    fn try_from(value: &'a ChangeAggregation<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}

impl<D> Display for ChangeAggregation<D>
where
    D: RelatedData + Clone + Display + Default,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.get_root() {
            Some(root) => write!(f, "{}", root),
            None => write!(f, "Empty aggregation."),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct ChangeAggregationWithRng<'a, D, R>
where
    D: RelatedData + Clone,
    R: Rng + ?Sized,
{
    pub(crate) root: Option<AggregationNode<D>>,
    pub(crate) rng: &'a mut R,
}

impl<'a, D, R> ChangeAggregationWithRng<'a, D, R>
where
    D: RelatedData + Clone,
    R: Rng + ?Sized,
{
    pub fn new(rng: &'a mut R) -> Self {
        Self { root: None, rng }
    }

    pub fn get_root(&self) -> Option<&AggregationNode<D>> {
        self.root.as_ref()
    }
}

// impl<'a, G, R> ChangeAggregationWithRng<'a, ProverAggregationData<G>, R>
// where
//     R: Rng + ?Sized,
//     G: AffineRepr,
//     G::BaseField: PrimeField,
// {
//     pub fn extend(
//         &mut self,
//         changes: &BranchChange<G>,
//         artefacts: &ProverArtefacts<G>,
//         change_hint: BranchChangesTypeHint<G>,
//     ) -> Result<(), ARTError> {
//         let Self { root, rng } = self;
//         let root = root.get_or_insert_with(AggregationNode::<ProverAggregationData<G>>::default);
//
//         root.extend(rng, changes, artefacts, change_hint)
//     }
//
//     /// Updates art by applying changes. Also updates path_secrets and node_index.
//     pub fn update_key(
//         &mut self,
//         new_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//     ) -> Result<ArtUpdateOutput<G>, ARTError> {
//
//         let index = art.get_node_index().clone();
//         let (tk, change, artefacts) =
//             art.private_update_node_key(&index, new_secret_key, false)?;
//
//         self.extend(
//             &change,
//             &artefacts,
//             BranchChangesTypeHint::UpdateKey {
//                 pk: G::generator().mul(new_secret_key).into_affine(),
//             },
//         )?;
//
//         Ok((tk, change, artefacts))
//     }
//
//     pub fn make_blank(
//         &mut self,
//         path: &[Direction],
//         temporary_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//     ) -> Result<ArtUpdateOutput<G>, ARTError> {
//         let append_changes = matches!(
//             art.get_node_at(&path)?.get_status(),
//             Some(LeafStatus::Blank)
//         );
//
//         if append_changes {
//             return Err(ARTError::InvalidMergeInput);
//         }
//
//         let index = NodeIndex::from(path.to_vec());
//         let (tk, mut change, artefacts) = art.private_update_node_key(&index, temporary_secret_key, append_changes)?;
//         change.change_type = BranchChangeType::RemoveMember;
//
//         self.extend(
//             &change,
//             &artefacts,
//             BranchChangesTypeHint::MakeBlank {
//                 pk: G::generator().mul(temporary_secret_key).into_affine(),
//                 merge: append_changes,
//             },
//         )?;
//
//         art.get_mut_node_at(&path)?.set_status(LeafStatus::Blank)?;
//
//         if !append_changes {
//             art.public_art
//                 .update_branch_weight(&path, false)?;
//         }
//
//         Ok((tk, change, artefacts))
//     }
//
//     pub fn append_or_replace_node(
//         &mut self,
//         secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//     ) -> Result<ArtUpdateOutput<G>, ARTError> {
//         let path = match art.get_public_art().find_path_to_left_most_blank_node() {
//             Some(path) => path,
//             None => art.get_public_art().find_path_to_lowest_leaf()?,
//         };
//
//         let hint = matches!(art
//             .get_public_art()
//             .get_node(&NodeIndex::Direction(path.to_vec()))?
//             .get_status(),
//         Some(LeafStatus::Active));
//
//         let (tk, mut changes, artefacts) = art.private_add_node(secret_key)?;
//         changes.change_type = BranchChangeType::AddMember;
//
//         let ext_pk = match hint {
//             true => Some(
//                 art.get_public_art()
//                     .get_node(&NodeIndex::Direction(path.to_vec()))?
//                     .get_public_key(),
//             ),
//             false => None,
//         };
//
//         self.extend(
//             &changes,
//             &artefacts,
//             BranchChangesTypeHint::AppendNode {
//                 pk: G::generator().mul(secret_key).into_affine(),
//                 ext_pk,
//             },
//         )?;
//
//         Ok((tk, changes, artefacts))
//     }
//
//     pub fn leave(
//         &mut self,
//         new_secret_key: G::ScalarField,
//         art: &mut PrivateArt<G>,
//     ) -> Result<ArtUpdateOutput<G>, ARTError> {
//         let index = art.get_node_index().clone();
//         let (tk, mut change, artefacts) = art.private_update_node_key(&index, new_secret_key, false)?;
//         change.change_type = BranchChangeType::Leave;
//
//         self.extend(
//             &change,
//             &artefacts,
//             BranchChangesTypeHint::Leave {
//                 pk: G::generator().mul(new_secret_key).into_affine(),
//             },
//         )?;
//
//         art.get_mut_node(&index)?
//             .set_status(LeafStatus::PendingRemoval)?;
//
//         Ok((tk, change, artefacts))
//     }
// }

impl ChangeAggregation<ProverAggregationData<CortadoAffine>> {
    pub fn extend<R>(
        &mut self,
        rng: &mut R,
        changes: &BranchChange<CortadoAffine>,
        artefacts: &ProverArtefacts<CortadoAffine>,
        change_hint: BranchChangesTypeHint<CortadoAffine>,
    ) -> Result<(), ARTError>
    where
        R: Rng + ?Sized,
    {
        let root = self
            .root
            .get_or_insert_with(AggregationNode::<ProverAggregationData<CortadoAffine>>::default);

        root.extend(rng, changes, artefacts, change_hint)
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub fn update_key<'a, R>(
        &mut self,
        new_secret_key: Fr,
        art: &mut PrivateZeroArt<'a, R>,
    ) -> Result<ArtUpdateOutput<CortadoAffine>, ARTError>
    where
        R: Rng + ?Sized,
    {
        let index = art.get_node_index().clone();
        let (tk, change, artefacts) =
            art.private_art
                .private_update_node_key(&index, new_secret_key, false)?;

        self.extend(
            &mut art.rng,
            &change,
            &artefacts,
            BranchChangesTypeHint::UpdateKey {
                pk: CortadoAffine::generator().mul(new_secret_key).into_affine(),
            },
        )?;

        Ok((tk, change, artefacts))
    }

    pub fn remove_member<'a, R>(
        &mut self,
        path: &[Direction],
        temporary_secret_key: Fr,
        art: &mut PrivateZeroArt<'a, R>,
    ) -> Result<ArtUpdateOutput<CortadoAffine>, ARTError>
    where
        R: Rng + ?Sized,
    {
        let append_changes = matches!(
            art.get_node_at(path)?.get_status(),
            Some(LeafStatus::Blank)
        );

        if append_changes {
            return Err(ARTError::InvalidMergeInput);
        }

        let index = NodeIndex::from(path.to_vec());
        let (tk, mut change, artefacts) = art.private_art.private_update_node_key(
            &index,
            temporary_secret_key,
            append_changes,
        )?;
        change.change_type = BranchChangeType::RemoveMember;

        self.extend(
            &mut art.rng,
            &change,
            &artefacts,
            BranchChangesTypeHint::RemoveMember {
                pk: CortadoAffine::generator()
                    .mul(temporary_secret_key)
                    .into_affine(),
                merge: append_changes,
            },
        )?;

        art.get_mut_node_at(path)?.set_status(LeafStatus::Blank)?;

        if !append_changes {
            art.private_art
                .public_art
                .update_branch_weight(path, false)?;
        }

        Ok((tk, change, artefacts))
    }

    pub fn add_member<'a, R>(
        &mut self,
        secret_key: Fr,
        art: &mut PrivateZeroArt<'a, R>,
    ) -> Result<ArtUpdateOutput<CortadoAffine>, ARTError>
    where
        R: Rng + ?Sized,
    {
        let path = match art.get_public_art().find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => art.get_public_art().find_path_to_lowest_leaf()?,
        };

        let hint = matches!(
            art.get_public_art()
                .get_node(&NodeIndex::Direction(path.to_vec()))?
                .get_status(),
            Some(LeafStatus::Active)
        );

        let (tk, mut changes, artefacts) = art.private_art.private_add_node(secret_key)?;
        changes.change_type = BranchChangeType::AddMember;

        let ext_pk = match hint {
            true => Some(
                art.get_public_art()
                    .get_node(&NodeIndex::Direction(path.to_vec()))?
                    .get_public_key(),
            ),
            false => None,
        };

        self.extend(
            &mut art.rng,
            &changes,
            &artefacts,
            BranchChangesTypeHint::AddMember {
                pk: CortadoAffine::generator().mul(secret_key).into_affine(),
                ext_pk,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    pub fn leave<'a, R>(
        &mut self,
        new_secret_key: Fr,
        art: &mut PrivateZeroArt<'a, R>,
    ) -> Result<ArtUpdateOutput<CortadoAffine>, ARTError>
    where
        R: Rng + ?Sized,
    {
        let index = art.get_node_index().clone();
        let (tk, mut change, artefacts) =
            art.private_art
                .private_update_node_key(&index, new_secret_key, false)?;
        change.change_type = BranchChangeType::Leave;

        self.extend(
            &mut art.rng,
            &change,
            &artefacts,
            BranchChangesTypeHint::Leave {
                pk: CortadoAffine::generator().mul(new_secret_key).into_affine(),
            },
        )?;

        art.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        Ok((tk, change, artefacts))
    }
}

impl ChangeAggregation<ProverAggregationData<CortadoAffine>> {
    pub fn prove<'a, R>(
        &self,
        art: &PrivateZeroArt<'a, R>,
        ad: &[u8],
        eligibility: Option<EligibilityArtefact>,
    ) -> Result<PlainChangeAggregationWithProof<CortadoAffine>, ARTError>
    where
        R: Rng + ?Sized,
    {
        // Use some auxiliary keys for proof
        let eligibility = match eligibility {
            Some(eligibility) => eligibility,
            None => art.get_member_current_eligibility()?,
        };

        // Get ProverAggregationTree for proof.
        let prover_tree = ProverAggregationTree::try_from(self)?;

        let context = art.prover_engine.new_context(ad, eligibility);
        let proof = context.prove_aggregated(&prover_tree)?;

        Ok((PlainChangeAggregation::try_from(self)?, proof))
    }
}

impl<G> ChangeAggregation<AggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn extend(
        &mut self,
        changes: &BranchChange<G>,
        artefacts: &ProverArtefacts<G>,
        change_hint: BranchChangesTypeHint<G>,
    ) -> Result<(), ARTError> {
        let root = self
            .root
            .get_or_insert_with(AggregationNode::<AggregationData<G>>::default);

        root.extend(changes, artefacts, change_hint)
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub fn update_key(
        &mut self,
        new_secret_key: G::ScalarField,
        art: &mut PrivateArt<G>,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let index = art.get_node_index().clone();
        let (tk, change, artefacts) = art.private_update_node_key(&index, new_secret_key, false)?;

        self.extend(
            &change,
            &artefacts,
            BranchChangesTypeHint::UpdateKey {
                pk: G::generator().mul(new_secret_key).into_affine(),
            },
        )?;

        Ok((tk, change, artefacts))
    }

    pub fn remove_member(
        &mut self,
        path: &[Direction],
        temporary_secret_key: G::ScalarField,
        art: &mut PrivateArt<G>,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let append_changes = matches!(
            art.get_node_at(path)?.get_status(),
            Some(LeafStatus::Blank)
        );

        if append_changes {
            return Err(ARTError::InvalidMergeInput);
        }

        let index = NodeIndex::from(path.to_vec());
        let (tk, mut change, artefacts) =
            art.private_update_node_key(&index, temporary_secret_key, append_changes)?;
        change.change_type = BranchChangeType::RemoveMember;

        self.extend(
            &change,
            &artefacts,
            BranchChangesTypeHint::RemoveMember {
                pk: G::generator().mul(temporary_secret_key).into_affine(),
                merge: append_changes,
            },
        )?;

        art.get_mut_node_at(path)?.set_status(LeafStatus::Blank)?;

        if !append_changes {
            art.public_art.update_branch_weight(path, false)?;
        }

        Ok((tk, change, artefacts))
    }

    pub fn add_member(
        &mut self,
        secret_key: G::ScalarField,
        art: &mut PrivateArt<G>,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let path = match art.get_public_art().find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => art.get_public_art().find_path_to_lowest_leaf()?,
        };

        let hint = matches!(
            art.get_node(&NodeIndex::Direction(path.to_vec()))?
                .get_status(),
            Some(LeafStatus::Active)
        );

        let (tk, mut changes, artefacts) = art.private_add_node(secret_key)?;
        changes.change_type = BranchChangeType::AddMember;

        let ext_pk = match hint {
            true => Some(
                art.get_public_art()
                    .get_node(&NodeIndex::Direction(path.to_vec()))?
                    .get_public_key(),
            ),
            false => None,
        };

        self.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::AddMember {
                pk: G::generator().mul(secret_key).into_affine(),
                ext_pk,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    pub fn leave(
        &mut self,
        new_secret_key: G::ScalarField,
        art: &mut PrivateArt<G>,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let index = art.get_node_index().clone();
        let (tk, mut change, artefacts) =
            art.private_update_node_key(&index, new_secret_key, false)?;
        change.change_type = BranchChangeType::Leave;

        self.extend(
            &change,
            &artefacts,
            BranchChangesTypeHint::Leave {
                pk: G::generator().mul(new_secret_key).into_affine(),
            },
        )?;

        art.get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        Ok((tk, change, artefacts))
    }
}

impl<'a, D1, D2, R> TryFrom<&'a ChangeAggregationWithRng<'a, D1, R>> for ChangeAggregation<D2>
where
    D1: RelatedData + Clone + Default,
    D2: From<D1> + RelatedData + Clone + Default,
    AggregationNode<D2>: TryFrom<&'a AggregationNode<D1>, Error = ARTError>,
    R: Rng + ?Sized,
{
    type Error = ARTError;

    fn try_from(value: &'a ChangeAggregationWithRng<'a, D1, R>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(ChangeAggregation::default()),
            Some(root) => Ok(ChangeAggregation {
                root: Some(AggregationNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D, G> TryFrom<&'a ChangeAggregation<D>> for ProverAggregationTree<G>
where
    G: AffineRepr,
    D: RelatedData + Clone + Default,
    Self: TryFrom<&'a AggregationNode<D>, Error = ARTError>,
{
    type Error = <Self as TryFrom<&'a AggregationNode<D>>>::Error;

    fn try_from(value: &'a ChangeAggregation<D>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}
