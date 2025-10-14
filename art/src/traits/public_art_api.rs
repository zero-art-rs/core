use crate::types::{AggregationData, ChangeAggregation, UpdateData, VerifierAggregationData};
use crate::{
    errors::ARTError,
    types::{
        ARTNode, ARTRootKey, BranchChanges, Direction, NodeIndex, ProverArtefacts,
        VerifierArtefacts,
    },
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

pub trait ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Brute-force depth-first search in a tree for a leaf node that matches the given public key. Returns the
    /// path from root to the node.
    fn get_path_to_leaf(&self, public_key: &G) -> Result<Vec<Direction>, ARTError>;

    /// Brute-force depth-first search in a tree for a node node with the corresponding
    /// `public_key`.
    fn get_node_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError>;

    /// Brute-force depth-first search in a tree for a node node with the corresponding
    /// `public_key`. Return the reference to the node, if it exists.
    fn get_mut_node_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError>;

    /// Brute-force depth-first search in a tree for a leaf node with the corresponding
    /// `public_key`.
    fn get_leaf_with(&self, public_key: &G) -> Result<&ARTNode<G>, ARTError>;

    /// Brute-force depth-first search in a tree for a leaf node with the corresponding
    /// `public_key`. Return the reference to the node, if it exists.
    fn get_mut_leaf_with(&mut self, public_key: &G) -> Result<&mut ARTNode<G>, ARTError>;

    /// Recomputes art root key using the given leaf secret key. Returns additional artifacts for
    /// proof creation. The method will work only if all the nodes on path from root to leaf are
    /// the result of Diffie-Hellman key exchanged. The result might be unpredictable, is case when
    /// there is any node on a path which where merged from several changes. Users, which want
    /// to join the art, should update their secret key to initialize the `path_secrets`.
    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: &NodeIndex,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

    /// Returns helper structure for verification of art update.
    fn compute_artefacts_for_verification(
        &self,
        branch_changes: &BranchChanges<G>,
    ) -> Result<VerifierArtefacts<G>, ARTError>;

    /// Shorthand for computing public key to given secret.
    fn public_key_of(&self, secret: &G::ScalarField) -> G;

    /// Extends or replaces the leaf on a path with new node. New node contains public key
    /// corresponding to a given secret key. Then it updates the necessary public keys on a
    /// path to root using new node's temporary secret key. Returns new ARTRootKey and
    /// BranchChanges for other users.
    fn append_or_replace_node_in_public_art(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<UpdateData<G>, ARTError>;

    /// Replaces the leaf at the given `path` with a given `temporary_secret_key`. Also updates
    /// the branch up to the root.
    ///
    /// # Returns
    /// * `ARTRootKey<G>` – New root key after applying the change.
    /// * `BranchChanges<G>` – Helper data for other users to apply the same update of the art.
    /// * `ProverArtefacts<G>` – Artefacts required for proving correctness of the update.
    fn make_blank_in_public_art(
        &mut self,
        path: &[Direction],
        temporary_secret_key: &G::ScalarField,
    ) -> Result<UpdateData<G>, ARTError>;

    /// Updates art public keys using public keys provided in changes. It doesn't change the art
    /// structure.
    fn update_art_with_changes(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
    ) -> Result<(), ARTError>;

    /// Returns node by the given `index`.
    fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError>;

    /// Returns node on the end of the given `path`.
    fn get_node_with_path(&self, path: &[Direction]) -> Result<&ARTNode<G>, ARTError>;

    /// Returns mutable node by the given `index`.
    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError>;

    /// Returns mutable node on the end of the given `path`.
    fn get_mut_node_with_path(&mut self, path: &[Direction]) -> Result<&mut ARTNode<G>, ARTError>;

    /// Updates art with given changes.
    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Updates art with given changes. Available options are:
    /// - `append_changes` - if false replace public keys with provided in changes, Else, append
    ///   them to the available ones.
    /// - `update_weights` - If true updates the weights of the art on make blank change. If
    ///   false, it will leve those weights as is. Can be used to correctly apply the second
    ///   blanking of some node.
    fn update_public_art_with_options(
        &mut self,
        changes: &BranchChanges<G>,
        append_changes: bool,
        update_weights: bool,
    ) -> Result<(), ARTError>;

    /// Merges given conflict changes into the art.
    fn merge_all(&mut self, target_changes: &[BranchChanges<G>]) -> Result<(), ARTError>;

    /// Merges given conflict changes into the art. Changes which are already applied (key_update)
    /// are passed into applied_changes. Other changes are not supported.
    fn merge_with_skip(
        &mut self,
        applied_changes: &[BranchChanges<G>],
        target_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError>;

    /// Retrieve aggregation co_path values from the art
    fn get_aggregation_co_path(
        &self,
        aggregation: &ChangeAggregation<AggregationData<G>>,
    ) -> Result<ChangeAggregation<VerifierAggregationData<G>>, ARTError>;
}

pub(crate) trait ARTPublicAPIHelper<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Returns a co-path to the leaf with a given public key. Co-path is a vector of public keys
    /// of nodes on path from user's leaf to root
    fn get_co_path_values(&self, index: &NodeIndex) -> Result<Vec<G>, ARTError>;

    /// Searches for the left most blank node and returns the vector of directions to it.
    fn find_path_to_left_most_blank_node(&self) -> Option<Vec<Direction>>;

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left branch.
    fn find_path_to_lowest_leaf(&self) -> Result<Vec<Direction>, ARTError>;

    /// Extends or replaces a leaf on the end of a given path with the given node. This method
    /// doesn't change other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc. The return value is true if the target node is extended
    /// with the other. Else it will be replaced.
    fn append_or_replace_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &[Direction],
    ) -> Result<bool, ARTError>;

    /// Converts the type of leaf on a given path to blank leaf by changing its public key on a temporary one.
    /// This method doesn't change other art nodes. To update art afterward, use update_art_with_secret_key
    /// or update_art_with_changes.
    fn make_blank_without_changes_with_options(
        &mut self,
        path: &[Direction],
        update_weights: bool,
    ) -> Result<(), ARTError>;

    /// This method will update all public keys on a path from the root to node. Using provided
    /// secret key, it will recompute all the public keys and change old ones. It is used
    /// internally in algorithms for art updateCan be used to update art after applied changes.
    fn update_art_branch_with_leaf_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &[Direction],
        append_changes: bool,
    ) -> Result<UpdateData<G>, ARTError>;

    /// Internal method, which changes art, structure, so it is possible to update public keys
    /// after add member changes without errors.
    fn prepare_structure_for_append_node_changes(
        &mut self,
        append_node_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError>;

    /// Merge ART changes into self. `merged_changes` are merge conflict changes, which are
    /// conflicting with `target_change` but are already merged. After calling of this method,
    /// `target_change` will become merged one. This method doesn't change the the art structure,
    /// so MakeBlank and AppendNode changes are not fully applied
    fn merge_change(
        &mut self,
        merged_changes: &[BranchChanges<G>],
        target_change: &BranchChanges<G>,
    ) -> Result<(), ARTError>;
}
