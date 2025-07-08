use crate::{ARTError, ARTNode, ARTPublicView, ARTRootKey, PublicART, ark_de, ark_se};
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

        Ok((
            Self {
                root: art.root,
                generator: art.generator,
                secret_key,
            },
            root_key,
        ))
    }

    pub fn from_public_art(public_art: &PublicART<G>, secret_key: &G::ScalarField) -> Self {
        Self {
            root: public_art.get_root().clone(),
            generator: public_art.get_generator().clone(),
            secret_key: secret_key.clone(),
        }
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
            &from_bytes::<PublicART<G>>(bytes).map_err(|e| ARTError::Postcard(e))?,
            secret_key,
        ))
    }

    pub fn from_string(
        canonical_json: &String,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Ok(Self::from_public_art(
            &serde_json::from_str::<PublicART<G>>(canonical_json)
                .map_err(|e| ARTError::SerdeJson(e))?,
            secret_key,
        ))
    }
}
