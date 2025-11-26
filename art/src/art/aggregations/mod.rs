use crate::art::{
    ArtAdvancedOps, ArtUpdateOutput, PrivateArt, ProverArtefacts, PublicArt, PublicMergeData,
};
use crate::art_node::{
    AggregationNodeWrapper, LeafStatus, NodePair, PriorityNodePair, TreeMethods, TreeNodeWrapper,
};
use crate::changes::ApplicableChange;
use crate::changes::aggregations::{
    AggregatedChange, AggregatedNodeWrapper, AggregationData, AggregationNode,
    AggregationNodeIterWithPath, AggregationTree, ProverAggregationData,
};
use crate::changes::branch_change::{BranchChange, BranchChangeType, BranchChangeTypeHint};
use crate::errors::ArtError;
use crate::helper_tools::recompute_artefacts;
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_std::iterable::Iterable;
use cortado::CortadoAffine;
use tracing::{debug, error, trace};
use zrt_zk::aggregated_art::ProverAggregationTree;

#[cfg(test)]
mod tests;

/// Context for Aggregation changes and their proof creation
pub struct AggregationContext<T, G>
where
    G: AffineRepr,
{
    pub(crate) prover_aggregation: AggregationTree<ProverAggregationData<G>>,
    pub(crate) operation_tree: T,
}

impl<T, G> AggregationContext<T, G>
where
    G: AffineRepr,
{
    pub fn get_operation_tree(&self) -> &T {
        &self.operation_tree
    }
}

impl<G> From<PrivateArt<G>> for AggregationContext<PrivateArt<G>, G>
where
    G: AffineRepr,
{
    fn from(operation_tree: PrivateArt<G>) -> Self {
        Self {
            prover_aggregation: Default::default(),
            operation_tree,
        }
    }
}

impl<'a, T> TryFrom<&'a AggregationContext<T, CortadoAffine>>
    for ProverAggregationTree<CortadoAffine>
{
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<T, CortadoAffine>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

impl<'a, T> TryFrom<&'a AggregationContext<T, CortadoAffine>> for AggregatedChange<CortadoAffine> {
    type Error = ArtError;

    fn try_from(value: &'a AggregationContext<T, CortadoAffine>) -> Result<Self, Self::Error> {
        Self::try_from(&value.prover_aggregation)
    }
}

impl<G> AggregationTree<ProverAggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn update_branch(
        &mut self,
        prover_artefacts: &ProverArtefacts<G>,
        update_path: &[Direction],
        type_hint: Option<BranchChangeTypeHint<G>>,
    ) -> Result<&mut AggregationNode<ProverAggregationData<G>>, ArtError> {
        if update_path.len() + 1 != prover_artefacts.path.len()
            || update_path.len() + 1 != prover_artefacts.secrets.len()
            || update_path.len() != prover_artefacts.co_path.len()
        {
            error!(
                "Fail to update branch with provided dimensions {{ update path ({}), \
                public path ({}), public co-path ({}) and secrets path ({}) }}",
                update_path.len(),
                prover_artefacts.path.len(),
                prover_artefacts.secrets.len(),
                prover_artefacts.co_path.len()
            );

            return Err(ArtError::InvalidBranchChange);
        }

        let mut current_node = self.root.get_or_insert_default();
        let root_pk = *prover_artefacts.path.last().ok_or(ArtError::NoChanges)?;
        let root_sk = *prover_artefacts.secrets.last().ok_or(ArtError::NoChanges)?;
        current_node.data.aggregate(root_pk, None, root_sk, None);

        let artefacts_iterator = update_path
            .iter()
            .zip(prover_artefacts.path[..update_path.len()].iter().rev())
            .zip(prover_artefacts.secrets[..update_path.len()].iter().rev())
            .zip(prover_artefacts.co_path.iter().rev())
            .map(|(((dir, pk), sk), co_pk)| (dir, pk, sk, co_pk));

        for (dir, pk, sk, co_pk) in artefacts_iterator {
            current_node = current_node.mut_child(*dir).get_or_insert_default();
            current_node.data.aggregate(*pk, Some(*co_pk), *sk, None);
        }

        if let Some(type_hint) = type_hint {
            current_node.data.update_change_type(type_hint);
        }

        Ok(current_node)
    }

    // /// Updates art by applying changes. Also updates path_secrets and node_index.
    // pub(crate) fn inner_update_key(
    //     &mut self,
    //     new_secret_key: G::ScalarField,
    //     art: &mut PrivateArt<G>,
    // ) -> Result<ArtUpdateOutput<G>, ArtError> {
    //     let index = art.node_index().clone();
    //     let (tk, change, artefacts) = art.add_member(&index, new_secret_key, false)?;
    //
    //     self.extend(
    //         &change,
    //         &artefacts,
    //         BranchChangeTypeHint::UpdateKey {
    //             pk: G::generator().mul(new_secret_key).into_affine(),
    //         },
    //     )?;
    //
    //     Ok((tk, change, artefacts))
    // }
    //
    // pub(crate) fn inner_remove_member(
    //     &mut self,
    //     path: &[Direction],
    //     temporary_secret_key: G::ScalarField,
    //     art: &mut PrivateArt<G>,
    // ) -> Result<ArtUpdateOutput<G>, ArtError> {
    //     let append_changes = matches!(art.node_at(path)?.status(), Some(LeafStatus::Blank));
    //
    //     if append_changes {
    //         return Err(ArtError::InvalidMergeInput);
    //     }
    //
    //     let index = NodeIndex::from(path.to_vec());
    //     let (tk, mut change, artefacts) =
    //         art.private_update_node_key(&index, temporary_secret_key, append_changes)?;
    //     change.change_type = BranchChangeType::RemoveMember;
    //
    //     self.extend(
    //         &change,
    //         &artefacts,
    //         BranchChangeTypeHint::RemoveMember {
    //             pk: G::generator().mul(temporary_secret_key).into_affine(),
    //             merge: append_changes,
    //         },
    //     )?;
    //
    //     art.mut_node_at(path)?.set_status(LeafStatus::Blank)?;
    //
    //     if !append_changes {
    //         art.public_art.update_weight(path, false)?;
    //     }
    //
    //     Ok((tk, change, artefacts))
    // }
    //
    // pub(crate) fn inner_add_member(
    //     &mut self,
    //     secret_key: G::ScalarField,
    //     art: &mut PrivateArt<G>,
    // ) -> Result<ArtUpdateOutput<G>, ArtError> {
    //     let path = art.get_public_art().find_place_for_new_node()?;
    //
    //     let hint = matches!(
    //         art.get_public_art()
    //             .get_node(&NodeIndex::Direction(path.to_vec()))?
    //             .get_status(),
    //         Some(LeafStatus::Active)
    //     );
    //
    //     let (tk, mut changes, artefacts) = art.private_add_node(secret_key)?;
    //     changes.change_type = BranchChangeType::AddMember;
    //
    //     let ext_pk = match hint {
    //         true => Some(
    //             art.get_public_art()
    //                 .get_node(&NodeIndex::Direction(path.to_vec()))?
    //                 .get_public_key(),
    //         ),
    //         false => None,
    //     };
    //
    //     self.extend(
    //         &changes,
    //         &artefacts,
    //         BranchChangeTypeHint::AddMember {
    //             pk: G::generator().mul(secret_key).into_affine(),
    //             ext_pk,
    //         },
    //     )?;
    //
    //     Ok((tk, changes, artefacts))
    // }
    //
    // pub(crate) fn inner_leave_group(
    //     &mut self,
    //     new_secret_key: G::ScalarField,
    //     art: &mut PrivateArt<G>,
    // ) -> Result<ArtUpdateOutput<G>, ArtError> {
    //     let index = art.get_node_index().clone();
    //     let (tk, mut change, artefacts) =
    //         art.private_update_node_key(&index, new_secret_key, false)?;
    //     change.change_type = BranchChangeType::Leave;
    //
    //     let hint = BranchChangeTypeHint::Leave{pk: G::generator().mul(new_secret_key).into_affine()};
    //     self.extend(&change, &artefacts, hint)?;
    //
    //     art.mut_node(&index)?
    //         .set_status(LeafStatus::PendingRemoval)?;
    //
    //     Ok((tk, change, artefacts))
    // }
}

impl<G> ArtAdvancedOps<G, ()> for AggregationContext<PrivateArt<G>, G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn add_member(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        let path = self.operation_tree.find_place_for_new_node()?;

        let target_node = self.operation_tree.root().node_at(&path)?;
        let target_status = target_node.status();
        let mut ext_pk = None;
        if matches!(target_status, Some(LeafStatus::Active)) {
            ext_pk = Some(target_node.public_key())
        };

        let (artefacts, change) = self
            .operation_tree
            .insert_or_extend_node_change(new_key, &path)?;

        let hint = BranchChangeTypeHint::AddMember {
            pk: G::generator().mul(new_key).into_affine(),
            ext_pk,
        };
        if ext_pk.is_some() {
            let mut update_path = path.to_vec();
            update_path.push(Direction::Right);
            self.prover_aggregation
                .update_branch(&artefacts, &update_path, None)?;

            let parent_node = self
                .prover_aggregation
                .mut_node_at(&path)
                .ok_or(ArtError::PathNotExists)?;
            parent_node.data.update_change_type(hint);
        } else {
            self.prover_aggregation
                .update_branch(&artefacts, &path, Some(hint))?;
        }

        self.operation_tree.apply(&change)?;
        self.operation_tree.commit()?;

        Ok(())
    }

    fn remove_member(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
    ) -> Result<(), ArtError> {
        let path = target_leaf.get_path()?;
        let append_changes = matches!(
            self.operation_tree.node_at(&path)?.status(),
            Some(LeafStatus::Blank)
        );

        if append_changes {
            return Err(ArtError::InvalidMergeInput);
        }

        let (artefacts, mut change) = self.operation_tree.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::RemoveMember;
        let hint = BranchChangeTypeHint::RemoveMember {
            pk: G::generator().mul(new_key).into_affine(),
            merge: append_changes,
        };
        self.prover_aggregation
            .update_branch(&artefacts, &target_leaf.get_path()?, Some(hint))?;

        self.operation_tree.apply(&change)?;
        self.operation_tree.commit()?;

        Ok(())
    }

    fn leave_group(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        let path = self.operation_tree.node_index().get_path()?;
        let (artefacts, mut change) = self.operation_tree.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::Leave;

        let hint = BranchChangeTypeHint::Leave {
            pk: G::generator().mul(new_key).into_affine(),
        };
        self.prover_aggregation
            .update_branch(&artefacts, &path, Some(hint))?;

        self.operation_tree.apply(&change)?;
        self.operation_tree.commit()?;

        Ok(())
    }

    fn update_key(&mut self, new_key: G::ScalarField) -> Result<(), ArtError> {
        let path = self.operation_tree.node_index().get_path()?;
        let (artefacts, mut change) = self.operation_tree.update_node_key_change(new_key, &path)?;
        change.change_type = BranchChangeType::UpdateKey;

        let hint = BranchChangeTypeHint::Leave {
            pk: G::generator().mul(new_key).into_affine(),
        };
        self.prover_aggregation
            .update_branch(&artefacts, &path, Some(hint))?;

        self.operation_tree.apply(&change)?;
        self.operation_tree.commit()?;

        Ok(())
    }
}

impl<G> AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn pub_art_unrecoverable_apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let Some(agg_root) = &self.root else {
            return Ok(());
        };

        for (node, path) in AggregationNodeIterWithPath::new(agg_root) {
            let full_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();
            let mut path = full_path.clone();

            let art_node_preview = art
                // .preview()
                .node_at(&full_path)
                .ok()
                .map(|node| node.public_key());

            let merge_node = if let Some(last_dir) = path.pop() {
                // update other nodes
                let merge_node = art
                    .merge_tree
                    .mut_node_at(&path)
                    .ok_or(ArtError::InvalidAggregation)?
                    .mut_child(last_dir);

                let merge_node = if let Some(merge_node) = merge_node {
                    merge_node
                } else {
                    if art_node_preview.is_some() {
                        merge_node.get_or_insert_default()
                    } else {
                        return Err(ArtError::InvalidAggregation);
                    }
                };

                merge_node
            } else {
                // Update root.
                art.merge_tree.root.get_or_insert_default()
            };

            if let Some(art_node_preview) = art_node_preview {
                merge_node.data.strong_key = Some(art_node_preview);
            }

            for change in &node.data.change_type {
                merge_node.apply(change)?;
            }

            merge_node.data.strong_key = Some(node.data.public_key);

            for change in &node.data.change_type {
                if let Some(increment) = match change {
                    BranchChangeTypeHint::AddMember { .. } => Some(true),
                    BranchChangeTypeHint::RemoveMember { merge: false, .. } => Some(false),
                    _ => None,
                } {
                    art.merge_tree
                        .mut_root()
                        .as_mut()
                        .ok_or(ArtError::InvalidAggregation)?
                        .update_weight(&path, increment)?;
                }
            }
        }

        Ok(())
    }

    pub fn aggregation_co_path(
        &self,
        art: &PrivateArt<G>,
        path: &[Direction],
    ) -> Result<Vec<G>, ArtError> {
        let mut partial_co_path = Vec::new();

        let mut agg_node = self.root();
        let mut art_node = Some(art.root());

        for dir in path {
            let co_agg_node = agg_node.and_then(|node| node.child(dir.other()));
            let co_art_node = art_node.and_then(|node| node.child(dir.other()));

            if let Some(agg_children) = co_agg_node {
                partial_co_path.push(agg_children.data.public_key);
            } else if let Some(art_children) = co_art_node {
                partial_co_path.push(art_children.public_key());
            } else {
                return Err(ArtError::InvalidAggregation);
            }

            agg_node = agg_node.and_then(|node| node.child(*dir));
            art_node = art_node.and_then(|node| node.child(*dir));
        }

        partial_co_path.reverse();
        Ok(partial_co_path)
    }

    pub fn private_art_secrets_unrecoverable_apply(
        &self,
        art: &mut PrivateArt<G>,
    ) -> Result<G::ScalarField, ArtError> {
        let Some(agg_root) = self.root() else {
            return Err(ArtError::NoChanges);
        };

        let path = art.node_index.get_path()?;

        let (level_sk, co_path) = if let Some(mut node) = self.node_at(&path) {
            // let mut secrets_increase = 0;
            let mut user_leaf_path = path.clone();
            while let Some(child) = node.child(Direction::Left) {
                user_leaf_path.push(Direction::Left);
                art.update_node_index(Direction::Left);
                art.secrets.extend_with(art.leaf_secret_key());

                node = child;
            }

            user_leaf_path.push(Direction::Left);
            art.update_node_index(Direction::Left);
            art.secrets.extend_with(art.leaf_secret_key());

            // user_leaf_path.push(Direction::Left);
            let co_path = self.aggregation_co_path(&art, &user_leaf_path)?;

            (art.leaf_secret_key(), co_path)
        } else {
            let intersection = agg_root.get_intersection(&path);

            let level_sk = art
                .secrets
                .secret(intersection.len() + 1)
                .ok_or(ArtError::InvalidBranchChange)?
                .key();

            let co_path = self.aggregation_co_path(&art, &path[..intersection.len() + 1])?;

            (level_sk, co_path)
        };

        let artefacts = recompute_artefacts(level_sk, &co_path)?;

        art.secrets.update(&artefacts.secrets[1..], false)?;

        Ok(*artefacts
            .secrets
            .last()
            .ok_or(ArtError::InvalidBranchChange)?)
    }

    pub(crate) fn private_art_unrecoverable_apply(
        &self,
        art: &mut PrivateArt<G>,
    ) -> Result<G::ScalarField, ArtError> {
        self.pub_art_unrecoverable_apply(&mut art.public_art)?;
        let tk = self.private_art_secrets_unrecoverable_apply(art)?;

        Ok(tk)
    }
}

impl<G> ApplicableChange<PublicArt<G>, ()> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PublicArt<G>) -> Result<(), ArtError> {
        let merge_tree_reserve_copy = art.merge_tree.clone();

        if let Err(err) = self.pub_art_unrecoverable_apply(art) {
            art.merge_tree = merge_tree_reserve_copy;
            return Err(err);
        }

        Ok(())
    }
}

impl<G> ApplicableChange<PrivateArt<G>, G::ScalarField> for AggregatedChange<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn apply(&self, art: &mut PrivateArt<G>) -> Result<G::ScalarField, ArtError> {
        let merge_tree_reserve_copy = art.public_art().merge_tree.clone();

        match self.private_art_unrecoverable_apply(art) {
            Err(err) => {
                art.public_art.merge_tree = merge_tree_reserve_copy;
                Err(err)
            }
            Ok(tk) => Ok(tk),
        }
    }
}
