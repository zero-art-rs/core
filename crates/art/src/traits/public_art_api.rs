use crate::types::BranchChangesType;
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
use cortado::CortadoAffine;

pub trait ARTPublicAPI<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: Sized,
{
    /// Returns a co-path to the leaf with a given public key.
    fn get_co_path_values(&self, path: &[Direction]) -> Result<Vec<G>, ARTError>;

    /// Brute-force depth-first search in a tree for a leaf node that matches the given public key. Returns the
    /// path from root to the node.
    fn get_path_to_leaf(&self, user_val: &G) -> Result<Vec<Direction>, ARTError>;

    /// Searches the tree for a leaf node that matches the given public key, and returns the
    /// index of a node. Searching algorithm is depth-first search.
    fn get_leaf_index(&self, user_val: &G) -> Result<u32, ARTError>;

    /// Recomputes art root key using the given leaf secret key.
    fn recompute_root_key_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<ARTRootKey<G>, ARTError>;

    /// Recomputes art root key using the given leaf secret key. returns additional artifacts for
    /// proof creation.
    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

    fn recompute_root_key_with_artefacts_using_secret_key_and_change(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
        changes: &BranchChanges<G>,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

    fn recompute_root_key_with_artefacts_for_merge(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
        changes: &Vec<BranchChanges<G>>,
    ) -> Result<(ARTRootKey<G>, ProverArtefacts<G>), ARTError>;

    /// Returns helper structure for verification of art changes
    fn compute_artefacts_for_verification(
        &self,
        branch_changes: &BranchChanges<G>,
    ) -> Result<VerifierArtefacts<G>, ARTError>;

    /// Shorthand for computing public key to given secret.
    fn public_key_of(&self, secret: &G::ScalarField) -> G;

    /// Update all public keys on path from the root to node, corresponding to the given secret
    /// key. Can be used to update art after applied changes.
    fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &[Direction],
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Changes old_secret_key secret key of a leaf to the new_secret_key.
    fn update_key_with_secret_key(
        &mut self,
        node_index: &NodeIndex,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Searches for the closest leaf to the root. Assume that the required leaf is in a subtree,
    /// with the smallest weight. Priority is given to left-most branch.
    fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, ARTError>;

    /// Extends a leaf on the end of a given path with the given node. This method don't change
    /// other nodes public keys. To update art, use update_art_with_secret_key,
    /// update_art_with_changes, etc.
    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &[Direction],
    ) -> Result<Option<Direction>, ARTError>;

    /// Extends the leaf on a path with new node. New node contains public key corresponding to a
    /// given secret key. Then it updates necessary public keys on a path to root using new
    /// node temporary secret key. Returns new ARTRootKey and BranchChanges for other users.
    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Converts the leaf on a given path to blank by changing its public key on a blank one.
    /// This method doesn't change other art nodes. To update art afterward, use update_art_with_secret_key
    /// or update_art_with_changes
    fn make_blank_without_changes(
        &mut self,
        path: &[Direction],
        temporary_public_key: &G,
    ) -> Result<(), ARTError>;

    /// Converts the leaf on a given path to temporary by changing its public key on given temporary
    /// one. At the end, updates necessary public keys on a path to root. Returns new ARTRootKey
    /// and BranchChanges for other users.
    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    /// Updates art public keys using public keys provided in changes. It doesn't change the art
    /// structure.
    fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Uses public keys provided in changes to change public keys of art.
    /// Those public keys are located on a path from root to node, corresponding to user, which
    /// provided changes.
    fn update_art_with_changes_and_path(
        &mut self,
        changes: &BranchChanges<G>,
        path: &[Direction],
    ) -> Result<(), ARTError>;

    /// Returns node by the given ARTNodeIndex
    fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError>;

    /// Returns mutable node by the given ARTNodeIndex
    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError>;

    /// This check says if the node can be immediately removed from a tree. Those cases are
    /// specific, so in general don't remove nodes and make them temporary instead
    fn can_remove(&mut self, lambda: &G::ScalarField, public_key: &G) -> Result<bool, ARTError>;

    /// Remove the last node in the given path if can
    fn remove_node(&mut self, path: &[Direction]) -> Result<(), ARTError>;

    /// Remove the last node in the given path if can and update public keys on a path from root to
    /// leaf
    fn remove_node_and_update_tree(
        &mut self,
        lambda: &G::ScalarField,
        public_key: &G,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError>;

    fn min_max_leaf_height(&self) -> Result<(u32, u32), ARTError>;

    fn get_disbalance(&self) -> Result<u32, ARTError>;

    /// Updates art with given changes.
    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError>;

    /// Merge the other art into self. Private art might have issues with merge, because it has a
    /// direction to self. weight_change can be used for correctness of merge, if the merging art
    /// fork has different number of nodes form the base art.
    fn merge_change(
        &mut self,
        merged_changes: &[BranchChanges<G>],
        target_change: &BranchChanges<G>,
    ) -> Result<(), ARTError>;

    /// Internal method, which changes art, structure, so it is possible to update public keys
    /// without errors.
    fn prepare_structure_for_append_node_changes(
        &mut self,
        append_node_changes: &[BranchChanges<G>],
    ) -> Result<(), ARTError>;

    /// Merges given conflict changes into the art.
    fn merge(&mut self, target_changes: &Vec<BranchChanges<G>>) -> Result<(), ARTError>;

    /// Merges given conflict changes into the art. If some key update changes are already applied, pass them
    /// into applied_changes. Other changes are not supported yet
    fn merge_with_skip(
        &mut self,
        applied_changes: &Vec<BranchChanges<G>>,
        target_changes: &Vec<BranchChanges<G>>,
    ) -> Result<(), ARTError>;
}
