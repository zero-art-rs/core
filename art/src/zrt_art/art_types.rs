use crate::errors::ARTError;
use crate::helper_tools::{ark_de, ark_se, iota_function, recompute_artefacts};
use crate::node_index::{Direction, NodeIndex};
use crate::zrt_art::art_node::{ArtNode, LeafIterWithPath, LeafStatus};
use crate::zrt_art::branch_change::{BranchChanges, BranchChangesType};
use crate::zrt_art::tree_node::TreeMethods;
use crate::zrt_art::{ArtLevel, ArtUpdateOutput, ProverArtefacts};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{PrimeField, Zero};
use ark_std::rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::error;
use zkp::toolbox::cross_dleq::PedersenBasis;

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
pub struct PublicZeroArt<G1, G2>
where
    G1: AffineRepr,
    G2: AffineRepr,
{
    pub(crate) public_art: PublicArt<G1>,
    pub(crate) proof_basis: PedersenBasis<G1, G2>,
}

pub struct PrivateZeroArt<'a, G1, G2, R>
where
    G1: AffineRepr,
    G2: AffineRepr,
    R: Rng + ?Sized,
{
    pub(crate) rng: &'a mut R,
    pub(crate) private_art: PrivateArt<G1>,
    pub(crate) proof_basis: PedersenBasis<G1, G2>,
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
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKey => {}
            BranchChangesType::AppendNode => {
                let leaf =
                    ArtNode::new_leaf(*changes.public_keys.last().ok_or(ARTError::NoChanges)?);
                self.append_or_replace_node_without_changes(leaf, &changes.node_index.get_path()?)?;
            }
            BranchChangesType::MakeBlank => {
                self.make_blank_without_changes_with_options(
                    &changes.node_index.get_path()?,
                    update_weights,
                )?;
            }
            BranchChangesType::Leave => {
                self.get_mut_node(&changes.node_index)?
                    .set_status(LeafStatus::PendingRemoval)?;
            }
        }

        self.update_art_with_changes(changes, append_changes)
    }

    /// Extends or replaces a leaf on the end of a given path with the given node. This method
    /// doesn't change other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc. The return value is true if the target node is extended
    /// with the other. Else it will be replaced.
    pub fn append_or_replace_node_without_changes(
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
    pub fn make_blank_without_changes_with_options(
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
    pub fn update_art_with_changes(
        &mut self,
        changes: &BranchChanges<G>,
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

        let (root, tk) = Self::compute_root_node(level_nodes, &mut level_secrets)?;

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

        let changes = BranchChanges {
            change_type: BranchChangesType::UpdateKey,
            public_keys: path_values,
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(path)?),
        };

        Ok((ark_level_secret_key, changes, artefacts))
    }

    /// Updates art by applying changes. Also updates path_secrets and node_index.
    pub(crate) fn update_private_art_with_options(
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
                        vec![*self.secrets.first().ok_or(ARTError::EmptyART)?];
                    new_path_secrets.append(self.secrets.clone().as_mut());
                    self.secrets = new_path_secrets;
                }
            }
        }

        self.public_art
            .update_with_options(changes, append_changes, update_weights)?;

        if let BranchChangesType::AppendNode = &changes.change_type {
            self.update_node_index()?;
        };

        let artefact_secrets = self.get_artefact_secrets_from_change(changes)?;

        self.zip_update_path_secrets(artefact_secrets, &changes.node_index, append_changes)?;

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
