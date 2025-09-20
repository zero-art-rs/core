use crate::traits::ARTPrivateAPI;
use crate::{
    errors::ARTError,
    helper_tools::{to_ark_scalar, to_dalek_scalar},
    traits::{ARTPrivateView, ARTPublicAPI, ARTPublicView},
    types::{ARTNode, ARTRootKey, NodeIndex, PrivateART, PublicART},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use postcard::{from_bytes, to_allocvec};
use std::mem;
use tracing::{debug, error};

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

    fn get_path_secrets(&self) -> &Vec<G::ScalarField> {
        &self.path_secrets
    }
    fn get_mut_path_secrets(&mut self) -> &mut Vec<G::ScalarField> {
        &mut self.path_secrets
    }

    fn set_path_secrets(&mut self, new_path_secrets: Vec<G::ScalarField>) -> Vec<G::ScalarField> {
        mem::replace(&mut self.path_secrets, new_path_secrets)
    }

    fn update_path_secrets_with(
        &mut self,
        mut other_path_secrets: Vec<G::ScalarField>,
        other: &NodeIndex,
    ) -> Result<(), ARTError> {
        let mut path_secrets = self.get_path_secrets().clone();

        if path_secrets.len() == 0 {
            return Err(ARTError::EmptyART);
        }

        if self.node_index.is_subpath_of(other)? {
            // Update path after update_key or append_node.
            let node_path = self.get_node_index().get_path()?;
            let other_node_path = other.get_path()?;

            return if node_path.len() == other_node_path.len() {
                self.set_path_secrets(other_path_secrets);
                Ok(())
            } else if node_path.len() + 1 == other_node_path.len() {
                other_path_secrets[0] = path_secrets.pop().ok_or(ARTError::EmptyART)?;
                self.set_path_secrets(other_path_secrets);

                Ok(())
            } else {
                Err(ARTError::InvalidInput)
            };
        }

        // It is a partial update of the path.
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;

        // Reverse secrets to perform computations starting from the root.
        other_path_secrets.reverse();
        path_secrets.reverse();

        // if path_secrets.len() != node_path.len() + 1 {
        //     debug!("Error: path_secrets.len() != node_path.len() + 1");
        //     return Err(ARTError::InvalidInput)
        // }

        // if other_path_secrets.len() != other_node_path.len() + 1 {
        //     debug!("Error: other_path_secrets.len() != other_node_path.len() + 1");
        //     return Err(ARTError::InvalidInput)
        // }

        // Always update art root key.
        path_secrets[0] = other_path_secrets[0];

        // Update other keys on the path.
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                path_secrets[i + 1] = other_path_secrets[i + 1];
            } else {
                break;
            }
        }

        // Reverse path_secrets back to normal order, and update change old secrets.
        path_secrets.reverse();
        self.set_path_secrets(path_secrets);

        Ok(())
    }

    fn merge_path_secrets(
        &mut self,
        other_path_secrets: &Vec<G::ScalarField>,
        other: &NodeIndex,
    ) -> Result<(), ARTError> {
        let node_path = self.get_node_index().get_path()?;
        let other_node_path = other.get_path()?;
        let path_secrets = self.get_mut_path_secrets();

        if path_secrets.len() == 0 {
            return Err(ARTError::EmptyART);
        }

        if path_secrets.len() == 1 {
            // ART has only one node
            if other_path_secrets.len() != 1 {
                // If path_secrets.len() is 1, then there are no other leaves
                return Err(ARTError::InvalidInput);
            }

            path_secrets[0] = path_secrets[0] + other_path_secrets[0];
            return Ok(());
        }

        let last_index = path_secrets.len() - 2;
        let other_last_index = other_path_secrets.len() - 2;

        path_secrets[last_index + 1] =
            path_secrets[last_index + 1] + other_path_secrets[other_last_index + 1];
        for (i, (a, b)) in node_path.iter().zip(other_node_path.iter()).enumerate() {
            if a == b {
                if other_last_index < i {
                    return Ok(());
                }

                if last_index < i {
                    error!(
                        "Failed to update path secrets, because provided path points on child node."
                    );
                    return Err(ARTError::InvalidInput);
                }

                path_secrets[last_index - i] =
                    path_secrets[last_index - i] + other_path_secrets[other_last_index - i];
            } else {
                return Ok(());
            }
        }

        Ok(())
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
        let secret_key = *secrets.get(0).ok_or(ARTError::InvalidInput)?;
        let (art, root_key) = PublicART::new_art_from_secrets(secrets, generator)?;

        Ok((Self::from_public_art(art, secret_key)?, root_key))
    }

    pub fn from_public_art(
        public_art: PublicART<G>,
        secret_key: G::ScalarField,
    ) -> Result<Self, ARTError> {
        let node_index =
            NodeIndex::from(public_art.get_path_to_leaf(&public_art.public_key_of(&secret_key))?);
        let (_, artefacts) = public_art
            .recompute_root_key_with_artefacts_using_secret_key(secret_key, &node_index)?;

        Ok(Self {
            root: public_art.root,
            generator: public_art.generator,
            secret_key,
            node_index,
            path_secrets: artefacts.secrets,
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

impl<G, A> TryFrom<(A, G::ScalarField)> for PrivateART<G>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    A: ARTPublicView<G> + ARTPublicAPI<G>,
{
    type Error = ARTError;

    fn try_from((mut other, secret_key): (A, G::ScalarField)) -> Result<Self, Self::Error> {
        // let node_index = NodeIndex::from(other.get_leaf_index(&other.public_key_of(&secret_key))?);
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
