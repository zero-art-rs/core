use crate::{
    errors::ARTError,
    traits::ARTPublicView,
    types::{ARTNode, ARTRootKey, NodeIndex},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;

pub trait ARTPrivateView<G>: ARTPublicView<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_secret_key(&self) -> G::ScalarField;

    fn set_secret_key(&mut self, secret_key: &G::ScalarField);

    fn get_root_key(&self) -> Result<ARTRootKey<G>, ARTError>;

    fn get_node_index(&self) -> &NodeIndex;

    fn set_node_index(&mut self, node_index: NodeIndex);

    fn update_node_index(&mut self) -> Result<(), ARTError>;

    fn new(
        root: Box<ARTNode<G>>,
        generator: G,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError>;

    fn get_path_secrets(&self) -> &Vec<Scalar>;

    fn get_mut_path_secrets(&mut self) -> &mut Vec<Scalar>;

    fn set_path_secrets(&mut self, new_path_secrets: Vec<Scalar>) -> Vec<Scalar>;

    fn update_path_secrets_with(
        &mut self,
        other_path_secrets: &Vec<Scalar>,
        other: &NodeIndex,
    ) -> Result<(), ARTError>;

    fn merge_path_secrets(
        &mut self,
        other_path_secrets: &Vec<Scalar>,
        other: &NodeIndex,
    ) -> Result<(), ARTError>;
}
