use crate::errors::ARTError;
use crate::helper_tools::recompute_artefacts;
use crate::traits::{ChildContainer, RelatedData};
use crate::types::{
    ARTNode, AggregationData, AggregationNodeIterWithPath, BranchChanges, BranchChangesTypeHint,
    ChangeAggregation, ChangeAggregationNode, ChangeAggregationWithRng, Direction, LeafStatus,
    NodeIndex, PrivateART, ProverAggregationData, ProverArtefacts, PublicART, UpdateData,
    VerifierAggregationData, VerifierChangeAggregation,
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_std::rand::Rng;
use std::fmt::{Display, Formatter};
use zrt_zk::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};

impl<D> ChangeAggregation<D>
where
    D: RelatedData + Clone,
{
    pub fn get_root(&self) -> Option<&ChangeAggregationNode<D>> {
        self.root.as_ref()
    }
}

impl<'a, D, R> ChangeAggregationWithRng<'a, D, R>
where
    D: RelatedData + Clone,
    R: Rng + ?Sized,
{
    pub fn new(rng: &'a mut R) -> Self {
        Self { root: None, rng }
    }

    pub fn get_root(&self) -> Option<&ChangeAggregationNode<D>> {
        self.root.as_ref()
    }
}

impl<'a, G, R> ChangeAggregationWithRng<'a, ProverAggregationData<G>, R>
where
    R: Rng + ?Sized,
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn extend(
        &mut self,
        changes: &BranchChanges<G>,
        artefacts: &ProverArtefacts<G>,
        change_hint: BranchChangesTypeHint<G>,
    ) -> Result<(), ARTError> {
        let Self { root, rng } = self;
        let root = root
            .get_or_insert_with(|| ChangeAggregationNode::<ProverAggregationData<G>>::default());

        root.extend(rng, changes, &artefacts, change_hint)
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
        art: &mut PrivateART<G>,
    ) -> Result<UpdateData<G>, ARTError> {
        let (tk, changes, artefacts) = art.update_key(new_secret_key)?;

        self.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::UpdateKey {
                pk: art.public_art.public_key_of(new_secret_key),
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    pub fn make_blank(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
        art: &mut PrivateART<G>,
    ) -> Result<UpdateData<G>, ARTError> {
        let merge = matches!(
            art.public_art.get_node_with_path(&path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        if merge {
            return Err(ARTError::InvalidMergeInput);
        }

        let (tk, changes, artefacts) = art.make_blank(path, temporary_secret_key)?;

        self.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::MakeBlank {
                pk: art.public_art.public_key_of(temporary_secret_key),
                merge,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    pub fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
        art: &mut PrivateART<G>,
    ) -> Result<UpdateData<G>, ARTError> {
        let path = match art.public_art.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => art.public_art.find_path_to_lowest_leaf()?,
        };

        let hint = art
            .public_art
            .get_node(&NodeIndex::Direction(path.to_vec()))?
            .is_active();

        let (tk, changes, artefacts) = art.append_or_replace_node(secret_key)?;

        let ext_pk = match hint {
            true => Some(
                art.public_art
                    .get_node(&NodeIndex::Direction(path.to_vec()))?
                    .get_public_key(),
            ),
            false => None,
        };

        self.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::AppendNode {
                pk: art.public_art.public_key_of(secret_key),
                ext_pk,
            },
        )?;

        Ok((tk, changes, artefacts))
    }

    pub fn leave(
        &mut self,
        new_secret_key: &G::ScalarField,
        art: &mut PrivateART<G>,
    ) -> Result<UpdateData<G>, ARTError> {
        let (tk, changes, artefacts) = art.leave(*new_secret_key)?;

        self.extend(
            &changes,
            &artefacts,
            BranchChangesTypeHint::Leave {
                pk: art.public_art.public_key_of(new_secret_key),
            },
        )?;

        Ok((tk, changes, artefacts))
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
        art: &PrivateART<G>,
    ) -> Result<VerifierChangeAggregation<G>, ARTError> {
        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        let mut resulting_aggregation_root =
            ChangeAggregationNode::<VerifierAggregationData<G>>::try_from(agg_root)?;

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
            } else if let Ok(parent) = art
                .public_art
                .get_node(&NodeIndex::Direction(parent_path.clone()))
                && let Ok(other_child) = parent.get_child(&last_direction.other())
            {
                // Try to retrieve Co-path from the original ART
                other_child.get_public_key()
            } else {
                // Retrieve co-path as the last leaf on the path. Also apply all the changes on the path
                let mut path = parent_path.clone();
                path.push(last_direction.other());
                art.public_art
                    .get_last_public_key_on_path(agg_root, &path)?
            };
            resulting_target_node.data.co_public_key = Some(pk);
        }

        Ok(ChangeAggregation {
            root: Some(resulting_aggregation_root),
        })
    }
}

impl<G> ChangeAggregation<VerifierAggregationData<G>>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn update_public_art(&self, art: &mut PublicART<G>) -> Result<(), ARTError> {
        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        for (item, path) in AggregationNodeIterWithPath::new(agg_root) {
            let item_path = path.iter().map(|(_, dir)| *dir).collect::<Vec<_>>();

            for change_type in &item.data.change_type {
                match change_type {
                    BranchChangesTypeHint::MakeBlank {
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
                    BranchChangesTypeHint::AppendNode { pk, ext_pk } => {
                        art.update_branch_weight(&item_path, true)?;

                        art.get_mut_node(&NodeIndex::Direction(item_path.clone()))?
                            .extend_or_replace(ARTNode::new_leaf(*pk))?;

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
    pub fn update_private_art(&self, art: &mut PrivateART<G>) -> Result<(), ARTError> {
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
        art: &mut PublicART<G>,
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
                .children
                .get_child(path[i])
                .ok_or(ARTError::InvalidAggregation)?;
        }

        for i in skip..path.len() {
            current_agg_node = current_agg_node
                .children
                .get_child(path[i + skip])
                .ok_or(ARTError::InvalidAggregation)?;
            let target_node = art.get_mut_node_with_path(&path[0..i + 1])?;

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
        art: &mut PrivateART<G>,
    ) -> Result<(), ARTError> {
        let path_secrets = art.get_path_secrets().clone();

        let agg_root = match self.get_root() {
            Some(root) => root,
            None => return Err(ARTError::NoChanges),
        };

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if agg_root.contain(&art.get_node_index().get_path()?) {
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
            .filter(|change| matches!(change, BranchChangesTypeHint::AppendNode { .. }))
            .count();
        for dir in &intersection {
            partial_co_path.push(current_art_node.get_child(&dir.other())?.get_public_key());

            current_art_node = current_art_node.get_child(dir)?;
            current_agg_node = current_agg_node
                .children
                .get_child(*dir)
                .ok_or(ARTError::PathNotExists)?;

            add_member_counter += current_agg_node
                .data
                .change_type
                .iter()
                .filter(|change| matches!(change, BranchChangesTypeHint::AppendNode { .. }))
                .count();
        }

        intersection.push(node_path[intersection.len()].other());
        partial_co_path.push(agg_root.get_node(&*intersection)?.data.public_key);
        partial_co_path.reverse();

        // Compute path_secrets for aggregation.
        let resulting_path_secrets_len = art.get_path_secrets().len() + add_member_counter;
        let index = resulting_path_secrets_len - partial_co_path.len() - 1;
        let level_sk = art.get_path_secrets()[index];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, &partial_co_path)?;

        let mut new_path_secrets = art.get_path_secrets().clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        // Update node `path_secrets`
        art.set_path_secrets(new_path_secrets);

        Ok(())
    }
}

impl<'a, D1, D2, R> TryFrom<&'a ChangeAggregationWithRng<'a, D1, R>> for ChangeAggregation<D2>
where
    D1: RelatedData + Clone + Default,
    D2: From<D1> + RelatedData + Clone + Default,
    ChangeAggregationNode<D2>: TryFrom<&'a ChangeAggregationNode<D1>, Error = ARTError>,
    R: Rng + ?Sized,
{
    type Error = ARTError;

    fn try_from(value: &'a ChangeAggregationWithRng<'a, D1, R>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(ChangeAggregation::default()),
            Some(root) => Ok(ChangeAggregation {
                root: Some(ChangeAggregationNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D1, D2> TryFrom<&'a ChangeAggregation<D1>> for ChangeAggregation<D2>
where
    D1: RelatedData + Clone + Default,
    D2: From<D1> + RelatedData + Clone + Default,
    ChangeAggregationNode<D2>: TryFrom<&'a ChangeAggregationNode<D1>, Error = ARTError>,
{
    type Error = ARTError;

    fn try_from(value: &'a ChangeAggregation<D1>) -> Result<Self, Self::Error> {
        match &value.root {
            None => Ok(ChangeAggregation::default()),
            Some(root) => Ok(ChangeAggregation {
                root: Some(ChangeAggregationNode::<D2>::try_from(root)?),
            }),
        }
    }
}

impl<'a, D, G, R> TryFrom<&'a ChangeAggregationWithRng<'a, D, R>> for ProverAggregationTree<G>
where
    G: AffineRepr,
    D: RelatedData + Clone + Default,
    Self: TryFrom<&'a ChangeAggregationNode<D>, Error = ARTError>,
    R: Rng + ?Sized,
{
    type Error = <Self as TryFrom<&'a ChangeAggregationNode<D>>>::Error;

    fn try_from(value: &'a ChangeAggregationWithRng<'a, D, R>) -> Result<Self, Self::Error> {
        if let Some(root) = &value.root {
            Self::try_from(root)
        } else {
            Err(Self::Error::NoChanges)
        }
    }
}

impl<'a, D, G> TryFrom<&'a ChangeAggregation<D>> for VerifierAggregationTree<G>
where
    G: AffineRepr,
    D: RelatedData + Clone + Default,
    Self: TryFrom<&'a ChangeAggregationNode<D>, Error = ARTError>,
{
    type Error = <Self as TryFrom<&'a ChangeAggregationNode<D>>>::Error;

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
    D: RelatedData + Clone + Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.get_root() {
            Some(root) => write!(f, "{}", root),
            None => write!(f, "Empty aggregation."),
        }
    }
}
