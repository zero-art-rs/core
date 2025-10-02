use crate::traits::ARTPrivateAPI;
use crate::{
    errors::ARTError,
    traits::{ARTPrivateView, ARTPublicAPI, ARTPublicView},
    types::{ARTNode, ARTRootKey, NodeIndex, PrivateART, PublicART},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use std::mem;

impl<G> PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    /// Creates new PrivateART from provided `secrets`. The order of secrets is preserved:
    /// the leftmost leaf corresponds to the firsts secret in `secrets`.
    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        let secret_key = *secrets.first().ok_or(ARTError::InvalidInput)?;
        let (art, root_key) = PublicART::new_art_from_secrets(secrets, generator)?;

        Ok((Self::try_from((art, secret_key))?, root_key))
    }

    pub fn to_string(&self) -> Result<String, ARTError> {
        serde_json::to_string(&PublicART {
            root: self.root.clone(),
            generator: self.generator,
        })
        .map_err(ARTError::SerdeJson)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(&PublicART {
            root: self.root.clone(),
            generator: self.generator,
        })
        .map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &[u8], secret_key: &G::ScalarField) -> Result<Self, ARTError> {
        Self::try_from((
            from_bytes::<PublicART<G>>(bytes).map_err(ARTError::Postcard)?,
            *secret_key,
        ))
    }

    pub fn from_string(
        canonical_json: &str,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Self::try_from((
            serde_json::from_str::<PublicART<G>>(canonical_json).map_err(ARTError::SerdeJson)?,
            *secret_key,
        ))
    }
}

impl<G> ARTPublicView<G> for PrivateART<G>
where
    G: AffineRepr + CanonicalDeserialize + CanonicalSerialize,
    G::BaseField: PrimeField,
{
    fn get_root(&self) -> &ARTNode<G> {
        &self.root
    }

    fn get_mut_root(&mut self) -> &mut Box<ARTNode<G>> {
        &mut self.root
    }

    fn get_generator(&self) -> G {
        self.generator
    }

    fn replace_root(&mut self, new_root: Box<ARTNode<G>>) -> Box<ARTNode<G>> {
        mem::replace(&mut self.root, new_root)
    }
}

impl<G> ARTPrivateView<G> for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    fn get_secret_key(&self) -> G::ScalarField {
        self.secret_key
    }

    fn set_secret_key(&mut self, secret_key: &G::ScalarField) {
        self.secret_key = *secret_key;
    }

    fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    fn set_node_index(&mut self, node_index: NodeIndex) {
        self.node_index = node_index
    }

    fn get_path_secrets(&self) -> &Vec<G::ScalarField> {
        &self.path_secrets
    }

    fn get_mut_path_secrets(&mut self) -> &mut Vec<G::ScalarField> {
        &mut self.path_secrets
    }
}

impl<G, A> TryFrom<(A, G::ScalarField)> for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G> + ARTPublicAPI<G>,
{
    type Error = ARTError;

    fn try_from((mut other, secret_key): (A, G::ScalarField)) -> Result<Self, Self::Error> {
        let node_index =
            NodeIndex::from(other.get_path_to_leaf(&other.public_key_of(&secret_key))?)
                .as_index()?;
        let (_, artefacts) =
            other.recompute_root_key_with_artefacts_using_secret_key(secret_key, &node_index)?;
        let root = other.replace_root(Box::new(ARTNode::default()));

        Ok(Self {
            root,
            generator: other.get_generator(),
            secret_key,
            node_index,
            path_secrets: artefacts.secrets,
        })
    }
}

impl<G> PartialEq for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    Self: ARTPublicAPI<G>,
{
    fn eq(&self, other: &Self) -> bool {
        if self.root == other.root
            && self.generator == other.generator
            && self.get_root_key().ok() == other.get_root_key().ok()
        {
            return true;
        }

        false
    }
}
