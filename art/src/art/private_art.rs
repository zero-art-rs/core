use crate::art::{
    ARTNode, ARTRootKey, ArtUpdateOutput, BranchChanges, BranchChangesType, LeafStatus,
    ProverArtefacts, PublicART,
};
use crate::errors::ARTError;
use crate::helper_tools::{ark_de, ark_se, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use crate::tree_node::TreeNode;
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};
use std::mem;

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    /// Public part of the art
    public_art: PublicART<G>,

    /// Secret key of the leaf in the art. Used to compute toot secret key.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    secret_key: G::ScalarField,

    /// Index of a leaf, corresponding to the `secret_key`.
    node_index: NodeIndex,

    /// Set of secret keys on path from leaf (corresponding to the `secret_key`) to root.
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    path_secrets: Vec<G::ScalarField>,
}

impl<G> PrivateART<G>
where
    G: AffineRepr + CanonicalDeserialize + CanonicalSerialize,
    G::BaseField: PrimeField,
{
    pub fn new(
        public_art: PublicART<G>,
        secret_key: G::ScalarField,
        node_index: NodeIndex,
        path_secrets: Vec<G::ScalarField>,
    ) -> Self {
        Self {
            public_art,
            secret_key,
            node_index,
            path_secrets,
        }
    }

    /// Creates new PrivateART from provided `secrets`. The order of secrets is preserved:
    /// the leftmost leaf corresponds to the firsts secret in `secrets`.
    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        let secret_key = *secrets.first().ok_or(ARTError::InvalidInput)?;
        let (art, root_key) = PublicART::new_art_from_secrets(secrets, generator)?;

        Ok((Self::from_public_art_and_secret(art, secret_key)?, root_key))
    }

    /// Creates new ART tree from other art. Uses `secret_key` to recompute `path_secrets`, so
    /// might not work after merges.
    pub fn from_public_art_and_secret(
        mut other: PublicART<G>,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError> {
        let leaf_path = other.get_path_to_leaf(&other.public_key_of(&secret_key))?;
        let co_path = other.get_co_path_values(&leaf_path)?;
        let artefacts = recompute_artefacts(secret_key, &co_path)?;

        let root = mem::replace(other.get_mut_root(), Box::new(ARTNode::default()));

        Ok(Self::new(
            PublicART::new(root, other.get_generator()),
            secret_key,
            NodeIndex::from(leaf_path).as_index()?,
            artefacts.secrets,
        ))
    }

    /// Creates new PrivateART from `other` ART and `path_secrets`.
    pub fn from_public_art_and_path_secrets(
        mut other: PublicART<G>,
        path_secrets: Vec<G::ScalarField>,
    ) -> Result<Self, ARTError> {
        let secret_key = *path_secrets.first().ok_or(ARTError::InvalidInput)?;
        let leaf_path = other.get_path_to_leaf(&other.public_key_of(&secret_key))?;
        let root = mem::replace(other.get_mut_root(), Box::new(ARTNode::default()));

        Ok(Self::new(
            PublicART::new(root, other.get_generator()),
            secret_key,
            NodeIndex::from(leaf_path).as_index()?,
            path_secrets,
        ))
    }

    pub fn get_root(&self) -> &ARTNode<G> {
        self.public_art.get_root()
    }

    pub fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>> {
        self.public_art.get_mut_root()
    }

    pub fn get_generator(&self) -> G {
        self.public_art.get_generator()
    }

    pub fn get_secret_key(&self) -> G::ScalarField {
        self.secret_key
    }

    /// Returns actual root key, stored at the end of path_secrets.
    pub fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        Ok(ARTRootKey {
            key: *self.get_path_secrets().last().ok_or(ARTError::EmptyART)?,
            generator: self.get_generator(),
        })
    }

    pub fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    pub fn get_path_secrets(&self) -> &Vec<G::ScalarField> {
        &self.path_secrets
    }

    pub fn get_public_art(&self) -> &PublicART<G> {
        &self.public_art
    }

    pub fn get_mut_public_art(&mut self) -> &mut PublicART<G> {
        &mut self.public_art
    }

    /// Shorthand for computing public key to given secret.
    pub fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.get_public_art().public_key_of(secret)
    }

    /// Returns serde json string representation
    pub fn to_string(&self) -> Result<String, ARTError> {
        serde_json::to_string(&self.get_public_art()).map_err(ARTError::SerdeJson)
    }

    /// Serialize with postcard
    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(&self.get_public_art()).map_err(ARTError::Postcard)
    }

    /// Deserialize with postcard
    pub fn deserialize(bytes: &[u8], secret_key: &G::ScalarField) -> Result<Self, ARTError> {
        Self::from_public_art_and_secret(
            from_bytes::<PublicART<G>>(bytes).map_err(ARTError::Postcard)?,
            *secret_key,
        )
    }

    /// Deserialize from serde json string representation
    pub fn from_string(
        canonical_json: &str,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Self::from_public_art_and_secret(
            serde_json::from_str::<PublicART<G>>(canonical_json).map_err(ARTError::SerdeJson)?,
            *secret_key,
        )
    }

    /// Changes old_secret_key of a user leaf to the new_secret_key and update path_secrets.
    pub fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        self.set_secret_key(new_secret_key);

        let path = self.get_node_index().get_path()?;
        let (tk, changes, artefacts) = self
            .get_mut_public_art()
            .update_art_branch_with_leaf_secret_key(new_secret_key, &path, false)?;

        self.set_path_secrets(artefacts.secrets.clone());
        self.update_node_index()?;

        Ok((tk, changes, artefacts))
    }

    /// Converts a leaf node, which is on the given path, to blank one and update path_secrets
    pub fn make_blank(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let append_changes = matches!(
            self.get_public_art().get_node_at(path)?.get_status(),
            Some(LeafStatus::Blank)
        );
        let (mut tk, changes, artefacts) = self
            .get_mut_public_art()
            .make_blank(path, temporary_secret_key)?;

        if append_changes {
            tk.key += *self.get_path_secrets().last().ok_or(ARTError::EmptyART)?;
        }

        self.update_path_secrets(
            artefacts.secrets.clone(),
            &changes.node_index,
            append_changes,
        )?;

        Ok((tk, changes, artefacts))
    }

    /// Append new node to the tree or replace the blank one. It also updates `path_secrets`.
    pub fn append_or_replace_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        if self.get_path_secrets().is_empty() {
            return Err(ARTError::EmptyART);
        }

        let (tk, changes, artefacts) = self
            .get_mut_public_art()
            .append_or_replace_node(secret_key)?;
        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            // Extend path_secrets. Append additional leaf secret to the start.
            let mut new_path_secrets =
                vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
            new_path_secrets.append(self.get_path_secrets().clone().as_mut());
            self.set_path_secrets(new_path_secrets);
        }
        self.update_node_index()?;

        self.update_path_secrets(artefacts.secrets.clone(), &changes.node_index, false)?;

        Ok((tk, changes, artefacts))
    }

    /// Remove yourself from the art.
    pub fn leave(
        &mut self,
        new_secret_key: G::ScalarField,
    ) -> Result<ArtUpdateOutput<G>, ARTError> {
        let (tk, mut changes, artefacts) = self.update_key(&new_secret_key)?;
        let index = self.get_node_index().clone();
        self.get_mut_public_art()
            .get_mut_node(&index)?
            .set_status(LeafStatus::PendingRemoval)?;

        changes.change_type = BranchChangesType::Leave;

        Ok((tk, changes, artefacts))
    }

    /// Updates art by applying changes. Also updates `path_secrets` and `node_index`.
    pub fn update(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        if let BranchChangesType::MakeBlank = changes.change_type
            && matches!(
                self.get_public_art()
                    .get_node(&changes.node_index)?
                    .get_status(),
                Some(LeafStatus::Blank)
            )
        {
            self.update_private_art_with_options(changes, true, false)
        } else {
            self.update_private_art_with_options(changes, false, true)
        }
    }

    /// Update ART with `target_changes` for the user, which didnt participated it the
    /// merge conflict.
    pub fn merge_for_observer(
        &mut self,
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError> {
        let mut append_member_count = 0;
        for change in target_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_observer(target_changes)?;
        self.get_mut_public_art().merge_all(target_changes)?;

        Ok(())
    }

    /// Update ART with `target_changes`, if the user contributed to the merge conflict with his
    /// `applied_change`. Requires `base_fork`, which is the previous state of the ART, with
    /// unapplied user provided `applied_change`. Currently, it will fail if the first applied
    /// change is append_member.
    pub fn merge_for_participant(
        &mut self,
        applied_change: BranchChanges<G>,
        unapplied_changes: &[BranchChanges<G>],
        base_fork: Self,
    ) -> Result<(), ARTError> {
        // Currently, it will fail if the first applied change is append_member.
        if let BranchChangesType::AppendNode = applied_change.change_type {
            return Err(ARTError::InvalidMergeInput);
        }

        let mut append_member_count = 0;
        for change in unapplied_changes {
            if let BranchChangesType::AppendNode = change.change_type {
                if append_member_count > 1 {
                    return Err(ARTError::InvalidMergeInput);
                }

                append_member_count += 1;
            }
        }

        self.recompute_path_secrets_for_participant(unapplied_changes, base_fork)?;
        self.get_mut_public_art()
            .merge_with_skip(&[applied_change], unapplied_changes)?;

        Ok(())
    }

    pub(crate) fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>> {
        mem::replace(self.public_art.get_mut_root(), new_root)
    }

    pub(crate) fn set_secret_key(&mut self, secret_key: &G::ScalarField) {
        self.secret_key = *secret_key;
    }

    pub(crate) fn set_node_index(&mut self, node_index: NodeIndex) {
        self.node_index = node_index
    }

    pub(crate) fn get_mut_path_secrets(&mut self) -> &mut Vec<G::ScalarField> {
        &mut self.path_secrets
    }

    /// Changes path_secrets to the given ones.
    pub(crate) fn set_path_secrets(
        &mut self,
        new_path_secrets: Vec<G::ScalarField>,
    ) -> Vec<G::ScalarField> {
        mem::replace(self.get_mut_path_secrets(), new_path_secrets)
    }

    /// Updates users node index by researching it in a tree.
    pub(crate) fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self
            .get_public_art()
            .get_path_to_leaf(&self.get_public_art().public_key_of(&self.get_secret_key()))?;
        self.set_node_index(NodeIndex::Direction(path).as_index()?);

        Ok(())
    }

    /// If `append_changes` is false, works as `set_path_secrets`. In the other case, it will
    /// append secrets to available ones. Works correctly if `self.node_index` isn't a subpath
    /// of the `other`. The `other` is used to properly decide, which secrets did change.
    fn update_path_secrets(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
        append_changes: bool,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.is_empty() {
            return Err(ARTError::EmptyART);
        }

        if self.get_node_index().is_subpath_of(other)? {
            return Err(ARTError::InvalidInput);
        }

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
        self.set_path_secrets(path_secrets);

        Ok(())
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    fn update_private_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        // If your node is to be blanked, return error, as it is impossible to update
        // path secrets at that point.
        if self.get_node_index().is_subpath_of(&changes.node_index)? {
            match changes.change_type {
                BranchChangesType::MakeBlank => return Err(ARTError::InapplicableBlanking),
                BranchChangesType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                BranchChangesType::Leave => return Err(ARTError::InapplicableLeave),
                BranchChangesType::AppendNode => {
                    // Extend path_secrets. Append additional leaf secret to the start.
                    let mut new_path_secrets =
                        vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                    new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                    self.set_path_secrets(new_path_secrets);
                }
            }
        }

        self.get_mut_public_art()
            .update_with_options(changes, append_changes, update_weights)?;

        if let BranchChangesType::AppendNode = &changes.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(changes)?;

        self.update_path_secrets(artefact_secrets, &changes.node_index, append_changes)?;

        Ok(())
    }

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if the user
    /// didn't make any changes, which where merged. It is a wrapper for
    /// `recompute_path_secrets_for_participant`. The difference, is then for observer we cant
    /// merge all secrets, we need to apply one and then append others.
    fn recompute_path_secrets_for_observer(
        &mut self,
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError> {
        let old_secrets = self.get_path_secrets().clone();

        self.recompute_path_secrets_for_participant(target_changes, self.clone())?;

        // subtract default secrets from path_secrets
        let path_secrets = self.get_mut_path_secrets();
        for i in (0..old_secrets.len()).rev() {
            if path_secrets[i] != old_secrets[i] {
                path_secrets[i] -= old_secrets[i];
            } else {
                return Ok(());
            }
        }

        Ok(())
    }

    /// Recomputes path_secrets for conflict changes, which where merged. Applicable if user
    /// had made change for merge. The state of the ART without that change is the base_fork,
    /// which is required to properly merge changes. Note, that `target_changes` doesn't contain
    /// users update, because it merges all path_secrets to the self path_secrets.
    fn recompute_path_secrets_for_participant(
        &mut self,
        target_changes: &[BranchChanges<G>],
        base_fork: PrivateART<G>,
    ) -> Result<(), ARTError> {
        for change in target_changes {
            if self.get_node_index().is_subpath_of(&change.node_index)? {
                match change.change_type {
                    BranchChangesType::MakeBlank => return Err(ARTError::InapplicableBlanking),
                    BranchChangesType::UpdateKey => return Err(ARTError::InapplicableKeyUpdate),
                    BranchChangesType::Leave => return Err(ARTError::InapplicableLeave),
                    BranchChangesType::AppendNode => {
                        // Extend path_secrets. Append additional leaf secret to the start.
                        let mut new_path_secrets =
                            vec![*self.get_path_secrets().first().ok_or(ARTError::EmptyART)?];
                        new_path_secrets.append(self.get_path_secrets().clone().as_mut());
                        self.set_path_secrets(new_path_secrets);
                    }
                }
            }

            let secrets = base_fork.get_artefact_secrets_from_change(change)?;

            self.update_path_secrets(secrets, &change.node_index, true)?;
        }

        Ok(())
    }

    /// Returns secrets from changes (ordering from leaf to the root).
    fn get_artefact_secrets_from_change(
        &self,
        changes: &BranchChanges<G>,
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
        let path_length = self.get_path_secrets().len();
        let updated_path_len = partial_co_path.len();

        let level_sk = self.get_path_secrets()[path_length - updated_path_len - 1];

        let ProverArtefacts { secrets, .. } = recompute_artefacts(level_sk, partial_co_path)?;

        let mut new_path_secrets = self.get_path_secrets().clone();
        for (sk, i) in secrets.iter().rev().zip((0..new_path_secrets.len()).rev()) {
            new_path_secrets[i] = *sk;
        }

        Ok(new_path_secrets)
    }
}

impl<G> PartialEq for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn eq(&self, other: &Self) -> bool {
        if self.get_root() == other.get_root()
            && self.get_generator() == other.get_generator()
            && self.get_root_key().ok() == other.get_root_key().ok()
        {
            return true;
        }

        false
    }
}

impl<G> Eq for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
}
