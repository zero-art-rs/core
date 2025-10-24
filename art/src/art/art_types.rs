use crate::art::art_node::{ArtNode, LeafIterWithPath, LeafStatus};
use crate::art::artefacts::VerifierArtefacts;
use crate::changes::branch_change::{BranchChange, BranchChangeType};
use crate::TreeMethods;
use crate::art::{ArtLevel, ArtUpdateOutput, EligibilityProofInput, ProverArtefacts};
use crate::errors::ARTError;
use crate::helper_tools::{iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine;
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use bulletproofs::PedersenGens;
use cortado::{CortadoAffine, Fr};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::ops::Mul;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Default)]
#[serde(bound = "")]
pub struct PublicArt<G>
where
    G: AffineRepr,
{
    pub(crate) tree_root: ArtNode<G>,
}

#[derive(Debug, Clone, Default)]
pub struct PrivateArt<G>
where
    G: AffineRepr,
{
    pub(crate) public_art: PublicArt<G>,
    pub(crate) secrets: Vec<G::ScalarField>,
    pub(crate) node_index: NodeIndex,
}

#[derive(Clone)]
pub struct PublicZeroArt {
    pub(crate) public_art: PublicArt<CortadoAffine>,
    pub(crate) proof_basis: PedersenBasis<CortadoAffine, EdwardsAffine>,
}

pub struct PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    pub(crate) rng: &'a mut R,
    pub(crate) private_art: PrivateArt<CortadoAffine>,
    pub(crate) proof_basis: PedersenBasis<CortadoAffine, EdwardsAffine>,
}

impl<G> PublicArt<G>
where
    G: AffineRepr,
{
    /// Update weight of the branch for nodes on the given `path`. If `increment_weight` is `true`,
    /// then increment weight by one, else decrement it by one.
    pub(crate) fn update_branch_weight(
        &mut self,
        path: &[Direction],
        increment_weight: bool,
    ) -> Result<(), ARTError> {
        for i in 0..path.len() {
            let weight = self.get_mut_node_at(&path[0..i])?.get_mut_weight()?;

            if increment_weight {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }

        Ok(())
    }

    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    pub(crate) fn get_co_path_values(&self, path: &[Direction]) -> Result<Vec<G>, ARTError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in path {
            co_path_values.push(
                parent
                    .get_child(direction.other())
                    .ok_or(ARTError::InvalidInput)?
                    .get_public_key(),
            );
            parent = parent.get_child(*direction).ok_or(ARTError::InvalidInput)?;
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    /// Updates art with given changes. Available options are:
    /// - `append_changes` - if false replace public keys with provided in changes, Else, append
    ///   them to the available ones.
    /// - `update_weights` - If true updates the weights of the art on make blank change. If
    ///   false, it will leve those weights as is. Can be used to correctly apply the second
    ///   blanking of some node.
    pub(crate) fn update_with_options(
        &mut self,
        change: &BranchChange<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        match &change.change_type {
            BranchChangeType::UpdateKey => {}
            BranchChangeType::AddMember => {
                let leaf =
                    ArtNode::new_leaf(*change.public_keys.last().ok_or(ARTError::NoChanges)?);
                self.append_or_replace_node_without_changes(leaf, &change.node_index.get_path()?)?;
            }
            BranchChangeType::RemoveMember => {
                self.make_blank_without_changes_with_options(
                    &change.node_index.get_path()?,
                    update_weights,
                )?;
            }
            BranchChangeType::Leave => {
                self.get_mut_node(&change.node_index)?
                    .set_status(LeafStatus::PendingRemoval)?;
            }
        }

        self.update_art_with_changes(change, append_changes)
    }

    /// Extends or replaces a leaf on the end of a given path with the given node. This method
    /// doesn't change other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc. The return value is true if the target node is extended
    /// with the other. Else it will be replaced.
    pub(crate) fn append_or_replace_node_without_changes(
        &mut self,
        node: ArtNode<G>,
        path: &[Direction],
    ) -> Result<bool, ARTError> {
        let mut node_for_extension = self.get_mut_root();
        for direction in path {
            if node_for_extension.is_leaf() {
                // The last node weight is done automatically through the extension method in ArtNode
                break;
            }

            *node_for_extension.get_mut_weight()? += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension
                .get_mut_child(*direction)
                .ok_or(ARTError::InvalidInput)?;
        }
        let perform_extension = matches!(node_for_extension.get_status(), Some(LeafStatus::Active));
        node_for_extension.extend_or_replace(node)?;

        Ok(perform_extension)
    }

    /// Converts the type of leaf on a given path to blank leaf by changing its public key on a temporary one.
    /// This method doesn't change other art nodes. To update art afterward, use update_art_with_secret_key
    /// or update_art_with_changes.
    pub(crate) fn make_blank_without_changes_with_options(
        &mut self,
        path: &[Direction],
        update_weights: bool,
    ) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            if update_weights {
                *target_node.get_mut_weight()? -= 1;
            }
            target_node = target_node
                .get_mut_child(*direction)
                .ok_or(ARTError::InvalidInput)?;
        }

        target_node.set_status(LeafStatus::Blank)?;

        Ok(())
    }

    /// Updates art public keys using public keys provided in changes. It doesn't change the art
    /// structure.
    pub(crate) fn update_art_with_changes(
        &mut self,
        changes: &BranchChange<G>,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        if changes.public_keys.is_empty() {
            return Err(ARTError::InvalidInput);
        }

        let mut current_node = self.get_mut_root();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key_with_options(changes.public_keys[i], append_changes);
            current_node = current_node
                .get_mut_child(
                    *changes
                        .node_index
                        .get_path()?
                        .get(i)
                        .unwrap_or(&Direction::Right),
                )
                .ok_or(ARTError::InvalidInput)?;
        }

        current_node.set_public_key_with_options(
            changes.public_keys[changes.public_keys.len() - 1],
            append_changes,
        );

        Ok(())
    }

    /// Searches for the left most blank node and returns the vector of directions to it.
    pub(crate) fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>> {
        for (node, path) in LeafIterWithPath::new(self.get_root()) {
            if node.is_leaf() && !matches!(node.get_status(), Some(LeafStatus::Active)) {
                let mut node_path = Vec::with_capacity(path.len());

                for (_, dir) in path {
                    node_path.push(dir);
                }

                return Some(node_path);
            }
        }

        None
    }

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left branch.
    pub(crate) fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ARTError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate
                .get_child(Direction::Left)
                .ok_or(ARTError::InvalidInput)?;
            let r = candidate
                .get_child(Direction::Right)
                .ok_or(ARTError::InvalidInput)?;

            let next_direction = match l.get_weight() <= r.get_weight() {
                true => Direction::Left,
                false => Direction::Right,
            };

            next.push(next_direction);
            candidate = candidate
                .get_child(next_direction)
                .ok_or(ARTError::InvalidInput)?;
        }

        Ok(next)
    }

    /// Returns helper structure for verification of art update.
    pub(crate) fn compute_artefacts_for_verification(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<VerifierArtefacts<G>, ARTError> {
        let mut co_path = Vec::new();

        let mut parent = self.get_root();
        for direction in &changes.node_index.get_path()? {
            if parent.is_leaf() {
                if let BranchChangeType::AddMember = changes.change_type
                    && matches!(parent.get_status(), Some(LeafStatus::Active))
                {
                    // The current node is a part of the co-path
                    co_path.push(parent.get_public_key())
                }
            } else {
                co_path.push(
                    parent
                        .get_child(direction.other())
                        .ok_or(ARTError::PathNotExists)?
                        .get_public_key(),
                );
                parent = parent
                    .get_child(*direction)
                    .ok_or(ARTError::PathNotExists)?;
            }
        }

        co_path.reverse();

        Ok(VerifierArtefacts {
            path: changes.public_keys.iter().rev().cloned().collect(),
            co_path,
        })
    }

    /// Merges given conflict changes into the art.
    pub(crate) fn merge_all(&mut self, target_changes: &[BranchChange<G>]) -> Result<(), ARTError> {
        self.merge_with_skip(&[], target_changes)
    }

    /// Merges given conflict changes into the art. Changes which are already applied (key_update)
    /// are passed into applied_changes. Other changes are not supported.
    pub(crate) fn merge_with_skip(
        &mut self,
        applied_changes: &[BranchChange<G>],
        target_changes: &[BranchChange<G>],
    ) -> Result<(), ARTError> {
        for change in applied_changes {
            if let BranchChangeType::AddMember = change.change_type {
                return Err(ARTError::InvalidMergeInput);
            }
        }

        let mut key_update_changes = Vec::new();
        let mut make_blank_changes = Vec::new();
        let mut append_member_changes = Vec::new();

        for change in target_changes {
            match change.change_type {
                BranchChangeType::UpdateKey | BranchChangeType::Leave => {
                    key_update_changes.push(change.clone());
                }
                BranchChangeType::RemoveMember => {
                    make_blank_changes.push(change.clone());
                }
                BranchChangeType::AddMember => {
                    append_member_changes.push(change.clone());
                }
            }
        }

        if !append_member_changes.is_empty() {
            return Err(ARTError::InvalidMergeInput);
        }

        // merge all key update changes but skip whose from applied_changes
        let mut iteration_start = applied_changes.len();
        let mut changes = applied_changes.to_vec();
        let key_update_changes_len = key_update_changes.len();

        let mut previous_shift = key_update_changes.len();
        changes.extend(key_update_changes);
        for i in iteration_start..changes.len() {
            self.merge_change(&changes[0..i], &changes[i])?;
        }
        iteration_start += previous_shift;

        previous_shift = make_blank_changes.len();
        changes.extend(make_blank_changes);
        for i in iteration_start..changes.len() {
            let extend_node = matches!(
                self.get_node(&changes[i].node_index)?.get_status(),
                Some(LeafStatus::Active)
            );
            if key_update_changes_len == 0 && extend_node {
                self.update_with_options(&changes[i], false, true)?;
            } else {
                self.update_with_options(&changes[i], true, false)?;
            }
        }

        Ok(())
    }

    /// Merge ART changes into self. `merged_changes` are merge conflict changes, which are
    /// conflicting with `target_change` but are already merged. After calling of this method,
    /// `target_change` will become merged one. This method doesn't change the the art structure,
    /// so MakeBlank and AppendNode changes are not fully applied.
    pub(crate) fn merge_change(
        &mut self,
        merged_changes: &[BranchChange<G>],
        target_change: &BranchChange<G>,
    ) -> Result<(), ARTError> {
        let mut shared_paths = Vec::with_capacity(merged_changes.len());
        for change in merged_changes {
            shared_paths.push(change.node_index.get_path()?);
        }

        let target_path = target_change.node_index.get_path()?;
        for level in 0..=target_path.len() {
            let node = self.get_mut_node(&NodeIndex::Direction(target_path[0..level].to_vec()))?;
            if let BranchChangeType::AddMember = target_change.change_type
                && level < target_path.len()
            {
                *node.get_mut_weight()? += 1;
                // The last node weight will be computed when the structure is updated
            }

            if shared_paths.is_empty() {
                // There are no further conflicts so change public key
                node.set_public_key(target_change.public_keys[level]);
            } else {
                // Resolve conflict by adding public keys
                node.set_public_key(
                    node.get_public_key()
                        .add(target_change.public_keys[level])
                        .into_affine(),
                );
            }

            // Remove branches which are not conflicting with target one yet
            for j in (0..shared_paths.len()).rev() {
                if shared_paths[j].get(level) != target_path.get(level) {
                    shared_paths.remove(j);
                }
            }
        }

        Ok(())
    }
}

impl<G> PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    pub fn setup(secrets: &[G::ScalarField]) -> Result<Self, ARTError> {
        if secrets.is_empty() {
            return Err(ARTError::InvalidInput);
        }

        let mut level_nodes = Vec::with_capacity(secrets.len());
        let mut level_secrets = secrets.to_vec();

        // Process leaves of the tree
        for leaf_secret in secrets {
            level_nodes.push(Box::new(ArtNode::new_leaf(
                G::generator().mul(leaf_secret).into_affine(),
            )));
        }

        // Fully fit leaf nodes in the next level by combining only part of them
        if level_nodes.len() > 2 {
            (level_nodes, level_secrets) =
                Self::fit_leaves_in_one_level(level_nodes, level_secrets)?;
        }

        let (root, _) = Self::compute_root_node(level_nodes, &mut level_secrets)?;

        let public_art = PublicArt {
            tree_root: root.as_ref().to_owned(),
        };

        let pk = G::generator()
            .mul(secrets.first().ok_or(ARTError::EmptyART)?)
            .into_affine();
        let path = public_art.get_path_to_leaf_with(pk)?;
        let co_path = public_art.get_co_path_values(&path)?;
        let artefacts =
            recompute_artefacts(*secrets.get(0).ok_or(ARTError::InvalidInput)?, &co_path)?;

        Ok(Self {
            public_art,
            secrets: artefacts.secrets,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn new(mut public_art: PublicArt<G>, secret_key: G::ScalarField) -> Result<Self, ARTError> {
        let leaf_path =
            public_art.get_path_to_leaf_with(G::generator().mul(secret_key).into_affine())?;
        let co_path = public_art.get_co_path_values(&leaf_path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;

        Ok(Self {
            public_art,
            secrets: artefacts.secrets,
            node_index: NodeIndex::from(leaf_path).as_index()?,
        })
    }

    pub fn restore(
        public_art: PublicArt<G>,
        secrets: Vec<G::ScalarField>,
    ) -> Result<Self, ARTError> {
        let pk = G::generator()
            .mul(secrets.first().ok_or(ARTError::EmptyART)?)
            .into_affine();
        let path = public_art.get_path_to_leaf_with(pk)?;
        Ok(Self {
            public_art,
            secrets,
            node_index: NodeIndex::from(path),
        })
    }

    pub fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    pub fn get_leaf_secret_key(&self) -> Result<G::ScalarField, ARTError> {
        self.secrets.first().copied().ok_or(ARTError::EmptyART)
    }

    pub fn get_root_secret_key(&self) -> Result<G::ScalarField, ARTError> {
        self.secrets.last().copied().ok_or(ARTError::EmptyART)
    }

    pub fn get_secrets(&self) -> &Vec<G::ScalarField> {
        &self.secrets
    }

    pub fn get_leaf_public_key(&self) -> Result<G, ARTError> {
        Ok(G::generator()
            .mul(self.get_leaf_secret_key()?)
            .into_affine())
    }

    pub fn get_public_art(&self) -> &PublicArt<G> {
        &self.public_art
    }

    // /// Changes old_secret_key of a user leaf to the new_secret_key and update path_secrets.
    // pub(crate) fn update_key(
    //     &mut self,
    //     new_secret_key: G::ScalarField,
    // ) -> Result<ArtUpdateOutput<G>, ARTError> {
    //     // self.set_secret_key(new_secret_key);
    //
    //     let path = self.get_node_index().get_path()?;
    //     let (tk, changes, artefacts) =
    //         self.update_art_branch_with_leaf_secret_key(new_secret_key, &path, false)?;
    //
    //     self.secrets = artefacts.secrets.clone();
    //     self.update_node_index()?;
    //
    //     Ok((tk, changes, artefacts))
    // }

    /// This method will update all public keys on a path from the root to node. Using provided
    /// secret key, it will recompute all the public keys and change old ones. It is used
    /// internally in algorithms for art updateCan be used to update art after applied changes.
    pub(crate) fn update_art_branch_with_leaf_secret_key(
        &mut self,
        secret_key: G::ScalarField,
        path: &[Direction],
        append_changes: bool,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let mut next = path.to_vec();
        let mut public_key = G::generator().mul(secret_key).into_affine();

        let mut co_path_values = vec![];
        let mut path_values = vec![];
        let mut secrets = vec![secret_key];

        let mut ark_level_secret_key = secret_key;
        while let Some(next_child) = next.pop() {
            let mut parent = self.get_mut_root();
            for direction in &next {
                parent = parent
                    .get_mut_child(*direction)
                    .ok_or(ARTError::InvalidInput)?;
            }

            // Update public art
            parent
                .get_mut_child(next_child)
                .ok_or(ARTError::InvalidInput)?
                .set_public_key_with_options(public_key, append_changes);
            let other_child_public_key = parent
                .get_child(next_child.other())
                .ok_or(ARTError::InvalidInput)?
                .get_public_key();

            path_values.push(public_key);
            co_path_values.push(other_child_public_key);

            let common_secret = other_child_public_key
                .mul(ark_level_secret_key)
                .into_affine();

            ark_level_secret_key = iota_function(&common_secret)?;
            secrets.push(ark_level_secret_key);

            public_key = G::generator().mul(ark_level_secret_key).into_affine();
        }

        self.get_mut_root()
            .set_public_key_with_options(public_key, append_changes);
        path_values.push(public_key);

        let artefacts = ProverArtefacts {
            path: path_values.clone(),
            co_path: co_path_values,
            secrets,
        };

        path_values.reverse();

        let changes = BranchChange {
            change_type: BranchChangeType::UpdateKey,
            public_keys: path_values,
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(path)?),
        };

        Ok((ark_level_secret_key, changes, artefacts))
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub(crate) fn update_private_art_with_options(
        &mut self,
        change: &BranchChange<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        // If your node is to be blanked, return error, as it is impossible to update
        // path secrets at that point.
        if self.get_node_index().is_subpath_of(&change.node_index)? {
            match change.change_type {
                BranchChangeType::RemoveMember => return Err(ARTError::InapplicableBlanking),
                BranchChangeType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                BranchChangeType::Leave => return Err(ARTError::InapplicableLeave),
                BranchChangeType::AddMember => {
                    // Extend path_secrets. Append additional leaf secret to the start.
                    let mut new_path_secrets =
                        vec![*self.secrets.first().ok_or(ARTError::EmptyART)?];
                    new_path_secrets.append(self.secrets.clone().as_mut());
                    self.secrets = new_path_secrets;
                }
            }
        }

        self.public_art
            .update_with_options(change, append_changes, update_weights)?;

        if let BranchChangeType::AddMember = &change.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(change)?;

        self.zip_update_path_secrets(artefact_secrets, &change.node_index, append_changes)?;

        Ok(())
    }

    /// If `append_changes` is false, works as `set_path_secrets`. In the other case, it will
    /// append secrets to available ones. Works correctly if `self.node_index` isn't a subpath
    /// of the `other`. The `other` is used to properly decide, which secrets did change.
    pub(crate) fn zip_update_path_secrets(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.secrets.clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        // if self.get_node_index().is_subpath_of(other)? {
        //     return Err(ARTError::SubPath);
        // }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // Always update art root key.
        match append_changes {
            true => path_secrets[0] += other_path_secrets[0],
            false => path_secrets[0] = other_path_secrets[0],
        }

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                match append_changes {
                    true => path_secrets[i + 1] += other_path_secrets[i + 1],
                    false => path_secrets[i + 1] = other_path_secrets[i + 1],
                }
            } else {
                break;
            }
        }

        // Reverse path_secrets back to normal order, and update change old secrets.
        path_secrets.reverse();
        self.secrets = path_secrets;

        Ok(())
    }

    /// Updates users node index by researching it in a tree.
    pub(crate) fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self.get_path_to_leaf_with(self.get_leaf_public_key()?)?;
        self.node_index = NodeIndex::Direction(path).as_index()?;

        Ok(())
    }

    pub(crate) fn private_update_node_key(
        &mut self,
        target_leaf: &NodeIndex,
        new_key: G::ScalarField,
        append_changes: bool,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let path = target_leaf.get_path()?;
        let (tk, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, append_changes)?;

        self.zip_update_path_secrets(
            artefacts.secrets.clone(),
            &changes.node_index,
            append_changes,
        )?;

        Ok((tk, changes, artefacts))
    }

    pub(crate) fn private_add_node(
        &mut self,
        new_key: G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let mut path = match self.public_art.find_path_to_left_most_blank_node() {
            Some(path) => path,
            None => self.public_art.find_path_to_lowest_leaf()?,
        };

        let new_leaf = ArtNode::new_leaf(G::generator().mul(new_key).into_affine());
        let target_leaf = self.get_mut_node_at(&path)?;

        if !target_leaf.is_leaf() {
            return Err(ARTError::LeafOnly);
        }

        let extend_node = matches!(target_leaf.get_status(), Some(LeafStatus::Active));
        target_leaf.extend_or_replace(new_leaf)?;

        self.public_art.update_branch_weight(&path, true)?;

        if extend_node {
            path.push(Direction::Right);
        }

        let (tk, changes, artefacts) =
            self.update_art_branch_with_leaf_secret_key(new_key, &path, false)?;

        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            let mut new_path_secrets = vec![*self.secrets.first().ok_or(ARTError::EmptyART)?];
            new_path_secrets.append(self.secrets.clone().as_mut());
            self.secrets = new_path_secrets;
        }
        self.update_node_index()?;

        self.zip_update_path_secrets(artefacts.secrets.clone(), &changes.node_index, false)?;

        Ok((tk, changes, artefacts))
    }

    /// Update ART with `target_changes` for the user, which didnt participated it the
    /// merge conflict.
    pub(crate) fn merge_for_observer(
        &mut self,
        target_changes: &[BranchChange<G>],
    ) -> Result<(), ARTError> {
        let mut append_member_count = 0;
        for change in target_changes {
            if let BranchChangeType::AddMember = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_observer(target_changes)?;
        self.public_art.merge_all(target_changes)?;

        Ok(())
    }

    /// Update ART with `target_changes`, if the user contributed to the merge conflict with his
    /// `applied_change`. Requires `base_fork`, which is the previous state of the ART, with
    /// unapplied user provided `applied_change`. Currently, it will fail if the first applied
    /// change is append_member.
    pub(crate) fn merge_for_participant(
        &mut self,
        applied_change: BranchChange<G>,
        unapplied_changes: &[BranchChange<G>],
        base_fork: Self,
    ) -> Result<(), ARTError> {
        // Currently, it will fail if the first applied change is append_member.
        if let BranchChangeType::AddMember = applied_change.change_type {
            return Err(ARTError::InvalidMergeInput);
        }

        let mut append_member_count = 0;
        for change in unapplied_changes {
            if let BranchChangeType::AddMember = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_participant(unapplied_changes, base_fork)?;
        self.public_art
            .merge_with_skip(&[applied_change], unapplied_changes)?;

        Ok(())
    }

    /// Computes the ART assuming that `level_nodes` and `level_secrets` are a power of two. If
    /// they are not they can be lifted with `fit_leaves_in_one_level` method.
    fn compute_root_node(
        level_nodes: Vec<Box<ArtNode<G>>>,
        level_secrets: &mut [G::ScalarField],
    ) -> Result<(Box<ArtNode<G>>, G::ScalarField), ARTError> {
        let mut stack = Vec::with_capacity(level_nodes.len());

        let mut last_secret = G::ScalarField::zero();

        // stack contains node, and her conditional weight
        stack.push((level_nodes[0].clone(), 1));
        for (sk, node) in level_secrets.iter().zip(level_nodes).skip(1) {
            let mut right_node = node;
            let mut right_secret = *sk;
            let mut right_weight = 1;

            while let Some((left_node, left_weight)) = stack.pop() {
                if left_weight != right_weight {
                    // return the node bask and wait for it to be the same weight
                    stack.push((left_node, left_weight));
                    break;
                }

                let ark_common_secret =
                    iota_function(&left_node.get_public_key().mul(right_secret).into_affine())?;
                right_secret = ark_common_secret;
                last_secret = ark_common_secret;

                right_node = Box::new(ArtNode::new_internal_node(
                    G::generator().mul(&ark_common_secret).into_affine(),
                    left_node,
                    right_node,
                ));
                right_weight += left_weight;
            }

            // put the node to the end of stack
            stack.push((right_node, right_weight));
        }

        let (root, _) = stack.pop().ok_or(ARTError::ARTLogicError)?;

        Ok((root, last_secret))
    }

    fn fit_leaves_in_one_level(
        mut level_nodes: Vec<Box<ArtNode<G>>>,
        mut level_secrets: Vec<G::ScalarField>,
    ) -> Result<ArtLevel<G>, ARTError> {
        let mut level_size = 2;
        while level_size < level_nodes.len() {
            level_size <<= 1;
        }

        if level_size == level_nodes.len() {
            return Ok((level_nodes, level_secrets));
        }

        let excess = level_size - level_nodes.len();

        let mut upper_level_nodes = Vec::new();
        let mut upper_level_secrets = Vec::new();
        for _ in 0..(level_nodes.len() - excess) >> 1 {
            let left_node = level_nodes.remove(0);
            let right_node = level_nodes.remove(0);

            level_secrets.remove(0); // skip the first secret

            let common_secret = iota_function(
                &left_node
                    .get_public_key()
                    .mul(level_secrets.remove(0))
                    .into_affine(),
            )?;

            let node = ArtNode::new_internal_node(
                G::generator().mul(&common_secret).into_affine(),
                left_node,
                right_node,
            );

            upper_level_nodes.push(Box::new(node));
            upper_level_secrets.push(common_secret);
        }

        for _ in 0..excess {
            let first_node = level_nodes.remove(0);
            upper_level_nodes.push(first_node);
            let first_secret = level_secrets.remove(0);
            upper_level_secrets.push(first_secret);
        }

        Ok((upper_level_nodes, upper_level_secrets))
    }

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if user
    /// had made change for merge. The state of the ART without that change is the base_fork,
    /// which is required to properly merge changes. Note, that `target_changes` doesn't contain
    /// users update, because it merges all path_secrets to the self path_secrets.
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &[BranchChange<G>],
        base_fork: PrivateArt<G>,
    ) -> Result<(), ARTError> {
        for change in target_changes {
            if self.get_node_index().is_subpath_of(&change.node_index)? {
                match change.change_type {
                    BranchChangeType::RemoveMember => return Err(ARTError::InapplicableBlanking),
                    BranchChangeType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                    BranchChangeType::Leave => return Err(ARTError::InapplicableLeave),
                    BranchChangeType::AddMember => {
                        // Extend path_secrets. Append additional leaf secret to the start.
                        let mut new_path_secrets =
                            vec![*self.get_secrets().first().ok_or(ARTError::EmptyART)?];
                        new_path_secrets.append(self.get_secrets().clone().as_mut());
                        self.secrets = new_path_secrets;
                    }
                }
            }

            let secrets = base_fork.get_artefact_secrets_from_change(change)?;

            self.zip_update_path_secrets(secrets, &change.node_index, true)?;
        }

        Ok(())
    }

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if the user
    /// didn't make any changes, which where merged. It is a wrapper for
    /// `recompute_path_secrets_for_participant`. The difference, is then for observer we cant
    /// merge all secrets, we need to apply one and then append others.
    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &[BranchChange<G>],
    ) -> Result<(), ARTError> {
        let old_secrets = self.get_secrets().clone();

        self.recompute_path_secrets_for_participant(target_changes, self.clone())?;

        // subtract default secrets from path_secrets
        let path_secrets = &mut self.secrets;
        for i in (0..old_secrets.len()).rev() {
            if path_secrets[i] != old_secrets[i] {
                path_secrets[i] -= old_secrets[i];
            } else {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Returns secrets from changes (ordering from leaf to the root).
    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChange<G>,
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        let intersection = self.get_node_index().intersect_with(&changes.node_index)?;

        let mut co_path = Vec::new();
        let mut current_node = self.get_root();
        for dir in &intersection {
            co_path.push(
                current_node
                    .get_child(dir.other())
                    .ok_or(ARTError::InvalidInput)?
                    .get_public_key(),
            );
            current_node = current_node.get_child(*dir).ok_or(ARTError::InvalidInput)?;
        }

        if let Some(public_key) = changes.public_keys.get(intersection.len() + 1) {
            co_path.push(*public_key);
        }

        co_path.reverse();

        let secrets = self.get_partial_path_secrets(&co_path)?;

        Ok(secrets)
    }

    /// Instead of recomputing path secretes from the leaf to root, this method takes some secret
    /// key in `path_secrets`, considering previous are unchanged, and recomputes the remaining
    /// `path_secrets`, which have changed. `partial_co_path` is a co-path from some inner node to
    /// the root, required to compute secrets.
    fn get_partial_path_secrets(
        &self,
        partial_co_path: &[G],
    ) -> Result<Vec<G::ScalarField>, ARTError> {
        let path_length = self.secrets.len();
        let updated_path_len = partial_co_path.len();

        let level_sk = self.secrets[path_length - updated_path_len - 1];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, partial_co_path)?;

        let mut new_path_secrets = self.secrets.clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        Ok(new_path_secrets)
    }
}

impl PublicZeroArt {
    pub fn new(public_art: PublicArt<CortadoAffine>) -> Result<Self, ARTError> {
        let gens = PedersenGens::default();
        let proof_basis = PedersenBasis::<CortadoAffine, EdwardsAffine>::new(
            CortadoAffine::generator(),
            CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y),
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        Ok(Self {
            public_art,
            proof_basis,
        })
    }

    pub fn get_public_art(&self) -> &PublicArt<CortadoAffine> {
        &self.public_art
    }
}

impl<'a, R> PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    pub fn new(private_art: PrivateArt<CortadoAffine>, rng: &'a mut R) -> Result<Self, ARTError> {
        let gens = PedersenGens::default();
        let proof_basis = PedersenBasis::<CortadoAffine, EdwardsAffine>::new(
            CortadoAffine::generator(),
            CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y),
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );
        Ok(Self {
            rng,
            private_art,
            proof_basis,
        })
    }

    pub fn get_public_art(&self) -> &PublicArt<CortadoAffine> {
        &self.private_art.get_public_art()
    }

    pub fn get_node_index(&self) -> &NodeIndex {
        &self.private_art.node_index
    }

    pub fn get_leaf_secret_key(&self) -> Result<Fr, ARTError> {
        self.private_art
            .secrets
            .first()
            .copied()
            .ok_or(ARTError::EmptyART)
    }

    pub fn get_root_secret_key(&self) -> Result<Fr, ARTError> {
        self.private_art
            .secrets
            .last()
            .copied()
            .ok_or(ARTError::EmptyART)
    }

    pub fn get_leaf_public_key(&self) -> Result<CortadoAffine, ARTError> {
        Ok(CortadoAffine::generator()
            .mul(self.get_leaf_secret_key()?)
            .into_affine())
    }
}

// impl<G> Debug for PrivateArt<G>
// where
//     G: AffineRepr,
// {
//     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
//         f.debug_struct("PublicArt")
//             .field("public_art", &self.public_art)
//             .field("secrets", &self.secrets)
//             .field("node_index", &self.node_index)
//             .finish()
//     }
// }

impl<'a, R> Debug for PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicArt")
            .field("private_art", &self.private_art)
            .finish()
    }
}

impl<G> PartialEq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        if self.get_root() == other.get_root()
            && self.get_root_secret_key().ok() == other.get_root_secret_key().ok()
        {
            return true;
        }

        false
    }
}

impl<G> Eq for PrivateArt<G>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
}

impl<'a, R> PartialEq for PrivateZeroArt<'a, R>
where
    R: Rng + ?Sized,
{
    fn eq(&self, other: &Self) -> bool {
        self.private_art == other.private_art
    }
}

impl<'a, R> Eq for PrivateZeroArt<'a, R> where R: Rng + ?Sized {}
