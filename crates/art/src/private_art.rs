use crate::{ART, ARTError, ARTNode, ARTRootKey, BranchChanges, ark_de, ark_se};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use curve25519_dalek::Scalar;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(bound = "")]
pub struct PrivateART<G: AffineRepr + CanonicalSerialize + CanonicalDeserialize> {
    pub art: ART<G>,
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
        let (art, root_key) = ART::new_art_from_secrets(secrets, generator)?;

        Ok((Self { art, secret_key }, root_key))
    }

    pub fn recompute_root_key(&self) -> Result<ARTRootKey<G>, ARTError> {
        self.art.recompute_root_key(self.secret_key)
    }

    pub fn recompute_root_key_with_artefacts(
        &self,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError> {
        self.art.recompute_root_key_with_artefacts(self.secret_key)
    }

    pub fn get_root(&self) -> &Box<ARTNode<G>> {
        &self.art.get_root()
    }

    pub fn update_key(
        &mut self,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let result = self.art.update_key(&self.secret_key, new_secret_key);
        self.secret_key = new_secret_key.clone();

        result
    }

    pub fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        self.art.append_node(&secret_key)
    }

    pub fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        self.art.make_blank(public_key, temporary_secret_key)
    }

    pub fn update_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        self.art.update_art(changes)
    }

    pub fn to_string(&self) -> Result<String, ARTError> {
        self.art.to_string()
    }

    pub fn serialize(&self) -> Result<Vec<u8>, ARTError> {
        self.art.serialize()
    }

    pub fn from_string_and_secret_key(
        canonical_json: &String,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        let art: ART<G> = serde_json::from_str(canonical_json).map_err(ARTError::SerdeJson)?;

        Ok(Self {
            art,
            secret_key: secret_key.clone(),
        })
    }

    pub fn deserialize(
        bytes: &Vec<u8>,
        secret_key: &G::ScalarField,
    ) -> Result<Self, ARTError> {
        Ok(Self {
            art: ART::deserialize(&bytes)?,
            secret_key: secret_key.clone(),
        })
    }
}
