use crate::{
    errors::ARTError,
    helper_tools::{ark_de, ark_se},
    traits::ARTPublicAPI,
    types::{ARTNode, ARTRootKey, NodeIndex, PublicART},
};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
{
    pub root: Box<ARTNode<G>>,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub generator: G,
    #[serde(serialize_with = "ark_se", deserialize_with = "ark_de")]
    pub secret_key: G::ScalarField,
    pub node_index: NodeIndex,
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
        let secret_key = secrets[0].clone();
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
        })
    }

    pub fn to_string(&self) -> Result<String, ARTError> {
        serde_json::to_string(&PublicART {
            root: self.root.clone(),
            generator: self.generator.clone(),
        })
        .map_err(ARTError::SerdeJson)
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        to_allocvec(&PublicART {
            root: self.root.clone(),
            generator: self.generator.clone(),
        })
        .map_err(ARTError::Postcard)
    }

    pub fn deserialize(bytes: &Vec<u8>, secret_key: &G::ScalarField) -> Result<Self, ARTError> {
        Ok(Self::from_public_art(
            from_bytes::<PublicART<G>>(bytes).map_err(|e| ARTError::Postcard(e))?,
            *secret_key,
        )?)
    }

    pub fn from_string(
        canonical_json: &String,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Ok(Self::from_public_art(
            serde_json::from_str::<PublicART<G>>(canonical_json)
                .map_err(|e| ARTError::SerdeJson(e))?,
            *secret_key,
        )?)
    }
}
