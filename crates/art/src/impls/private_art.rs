use crate::{
    errors::ARTError,
    traits::{ARTPrivateView, ARTPublicAPI, ARTPublicView},
    types::{ARTNode, NodeIndex, PrivateART, PublicART},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::mem;
use postcard::{from_bytes, to_allocvec};
use crate::types::ARTRootKey;

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
        self.secret_key = secret_key.clone();
    }

    fn get_node_index(&self) -> &NodeIndex {
        &self.node_index
    }

    fn set_node_index(&mut self, node_index: NodeIndex) {
        self.node_index = node_index
    }

    fn update_node_index(&mut self) -> Result<(), ARTError> {
        let path = self.get_path_to_leaf(&self.public_key_of(&self.get_secret_key()))?;
        self.set_node_index(NodeIndex::Direction(path));

        Ok(())
    }

    fn new(
        root: Box<ARTNode<G>>,
        generator: G,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError> {
        let public_art = PublicART { root, generator };

        Self::from_public_art(public_art, secret_key)
    }
}


impl<G> PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    pub fn new_art_from_secrets(
        secrets: &Vec<G::ScalarField>,
        generator: &G,
    ) -> Result<(Self, ARTRootKey<G>), ARTError> {
        let secret_key = secrets[0];
        let (art, root_key) = PublicART::new_art_from_secrets(secrets, generator)?;

        Ok((Self::from_public_art(art, secret_key)?, root_key))
    }

    pub fn from_public_art(
        public_art: PublicART<G>,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError> {
        let node_index = public_art.get_leaf_index(&public_art.public_key_of(&secret_key))?;

        Ok(Self {
            root: public_art.root,
            generator: public_art.generator,
            secret_key,
            node_index: NodeIndex::Index(node_index),
            merged_changes: Vec::new(),
        })
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
        Self::from_public_art(
            from_bytes::<PublicART<G>>(bytes).map_err(ARTError::Postcard)?,
            *secret_key,
        )
    }

    pub fn from_string(
        canonical_json: &str,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Self::from_public_art(
            serde_json::from_str::<PublicART<G>>(canonical_json).map_err(ARTError::SerdeJson)?,
            *secret_key,
        )
    }
}

impl<G, A> TryFrom<(&A, G::ScalarField)> for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G> + ARTPublicAPI<G>,
{
    type Error = ARTError;

    fn try_from((other, sk): (&A, G::ScalarField)) -> Result<Self, Self::Error> {
        let node_index = other.get_leaf_index(&other.public_key_of(&sk))?;

        Ok(Self {
            root: Box::new(other.get_root().clone()),
            generator: other.get_generator(),
            secret_key: sk,
            node_index: NodeIndex::Index(node_index),
            merged_changes: Vec::new(),
        })
    }
}
