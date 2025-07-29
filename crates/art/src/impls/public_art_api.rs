use crate::{
    errors::ARTError,
    helper_tools::iota_function,
    traits::{ARTPublicAPI, ARTPublicView},
    types::{ARTNode, ARTRootKey, BranchChanges, BranchChangesType, Direction, NodeIndex},
};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::iterable::Iterable;
use curve25519_dalek::Scalar;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::cmp::{max, min};

impl<G, PublicART> ARTPublicAPI<G> for PublicART
where
    Self: Sized + Serialize + DeserializeOwned,
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    PublicART: ARTPublicView<G>,
{
    fn get_co_path_values(&self, path: &Vec<Direction>) -> Result<Vec<G>, ARTError> {
        let mut co_path_values = Vec::new();

        let mut parent = self.get_root();
        for direction in path {
            match direction {
                Direction::Left => {
                    co_path_values.push(parent.get_right()?.public_key);
                    parent = parent.get_left()?;
                }
                Direction::Right => {
                    co_path_values.push(parent.get_left()?.public_key);
                    parent = parent.get_right()?;
                }
                _ => return Err(ARTError::InvalidInput),
            }
        }

        co_path_values.reverse();
        Ok(co_path_values)
    }

    fn get_path_to_leaf(&self, user_val: &G) -> Result<Vec<Direction>, ARTError> {
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                if last_node.public_key.eq(user_val) {
                    next.pop();
                    return Ok(next);
                } else {
                    path.pop();
                    next.pop();
                }
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right()?.as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left()?.as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Err(ARTError::PathNotExists)
    }

    fn get_leaf_index(&self, user_val: &G) -> Result<u32, ARTError> {
        let next = self.get_path_to_leaf(user_val)?;

        Ok(NodeIndex::get_index_from_path(&next)?)
    }

    fn recompute_root_key_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<ARTRootKey<G>, ARTError> {
        let path = match node_index {
            Some(node_index) => node_index.get_path()?,
            None => self.get_path_to_leaf(&self.public_key_of(&secret_key))?,
        };

        let co_path_values = self.get_co_path_values(&path)?;

        let mut ark_secret = secret_key.clone();
        for public_key in co_path_values.iter() {
            let secret = iota_function(&public_key.mul(ark_secret).into_affine());
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
        }

        Ok(ARTRootKey {
            key: ark_secret,
            generator: self.get_generator().clone(),
        })
    }

    fn recompute_root_key_with_artefacts_using_secret_key(
        &self,
        secret_key: G::ScalarField,
        node_index: Option<&NodeIndex>,
    ) -> Result<(ARTRootKey<G>, Vec<G>, Vec<Scalar>), ARTError> {
        let path = match node_index {
            Some(node_index) => node_index.get_path()?,
            None => self.get_path_to_leaf(&self.public_key_of(&secret_key))?,
        };

        let co_path_values = self.get_co_path_values(&path)?;

        let mut ark_secret = secret_key.clone();
        let mut secrets: Vec<Scalar> = vec![Scalar::from_bytes_mod_order(
            (&secret_key.clone().into_bigint().to_bytes_le()[..])
                .try_into()
                .unwrap(),
        )];
        for public_key in co_path_values.iter() {
            let secret = iota_function(&public_key.mul(ark_secret).into_affine());
            secrets.push(secret.clone());
            ark_secret = G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes());
        }

        Ok((
            ARTRootKey {
                key: ark_secret,
                generator: self.get_generator().clone(),
            },
            co_path_values,
            secrets,
        ))
    }

    fn public_key_of(&self, secret: &G::ScalarField) -> G {
        self.get_generator().mul(secret).into_affine()
    }

    fn update_art_with_secret_key(
        &mut self,
        secret_key: &G::ScalarField,
        path: &Vec<Direction>,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        // let mut next = self.get_path_to_leaf(&self.public_key_of(secret_key))?;
        let mut next = path.clone();

        let mut changes = BranchChanges {
            change_type: BranchChangesType::UpdateKey,
            public_keys: Vec::new(),
            node_index: NodeIndex::Index(NodeIndex::get_index_from_path(&next.clone())?),
        };

        let mut public_key = self.public_key_of(secret_key);

        let mut ark_level_secret_key = secret_key.clone();
        while !next.is_empty() {
            let next_child = next.pop().unwrap();

            let mut parent = self.get_mut_root();
            for direction in &next {
                parent = parent.get_mut_child(direction)?;
            }

            parent
                .get_mut_child(&next_child)?
                .set_public_key(public_key);

            changes.public_keys.push(public_key);

            let other_child_public_key = parent.get_other_child(&next_child)?.public_key.clone();
            let common_secret = other_child_public_key
                .mul(ark_level_secret_key)
                .into_affine();
            let level_secret_key = iota_function(&common_secret);
            ark_level_secret_key =
                G::ScalarField::from_le_bytes_mod_order(&level_secret_key.to_bytes());
            public_key = self
                .get_generator()
                .mul(&ark_level_secret_key)
                .into_affine();
        }

        self.get_mut_root().set_public_key(public_key);
        changes.public_keys.push(public_key);
        changes.public_keys.reverse();

        let key = ARTRootKey {
            key: ark_level_secret_key,
            generator: self.get_generator().clone(),
        };

        Ok((key, changes))
    }

    fn update_key_with_secret_key(
        &mut self,
        node_index: &NodeIndex,
        new_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let new_public_key = self.public_key_of(new_secret_key);

        let user_node = self.get_mut_node(node_index)?;
        user_node.set_public_key(new_public_key);

        self.update_art_with_secret_key(&new_secret_key, &node_index.get_path()?)
    }

    fn find_path_to_possible_leaf_for_insertion(&self) -> Result<Vec<Direction>, ARTError> {
        let mut candidate = self.get_root();
        let mut next = vec![];

        while !candidate.is_leaf() {
            let l = candidate.get_left()?;
            let r = candidate.get_right()?;

            match l.weight <= r.weight {
                true => {
                    next.push(Direction::Left);
                    candidate = candidate.get_left()?;
                }
                false => {
                    next.push(Direction::Right);
                    candidate = candidate.get_right()?;
                }
            }
        }

        Ok(next)
    }

    fn append_node_without_changes(
        &mut self,
        node: ARTNode<G>,
        path: &Vec<Direction>,
    ) -> Result<Direction, ARTError> {
        let mut node_for_extension = self.get_mut_root();
        for direction in path {
            node_for_extension.weight += 1; // The weight of every node is increased by 1
            node_for_extension = node_for_extension.get_mut_child(direction)?;
        }

        // The last node weight is done automatically through the extension methods
        node_for_extension.weight -= 1;
        let next_node_direction = match !node_for_extension.is_blank {
            true => Direction::Right,
            false => Direction::NoDirection,
        };
        node_for_extension.extend_or_replace(node)?;

        Ok(next_node_direction)
    }

    fn append_node(
        &mut self,
        secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let mut path = self.find_path_to_possible_leaf_for_insertion()?;
        let node = ARTNode::new_leaf(self.public_key_of(&secret_key));
        let node_index = NodeIndex::Index(NodeIndex::get_index_from_path(&path)?);

        let next = self.append_node_without_changes(node.clone(), &path)?;
        match next {
            Direction::Right => path.push(Direction::Right),
            _ => {}
        }

        self.update_art_with_secret_key(secret_key, &path)
            .map(|(root_key, mut changes)| {
                changes.node_index = node_index;
                changes.change_type = BranchChangesType::AppendNode(node);
                (root_key, changes)
            })
    }

    fn make_blank_without_changes(
        &mut self,
        path: &Vec<Direction>,
        temporary_public_key: &G,
    ) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in path {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }
        target_node.make_blank(temporary_public_key)?;

        Ok(())
    }

    fn make_blank(
        &mut self,
        public_key: &G,
        temporary_secret_key: &G::ScalarField,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        let new_public_key = self.public_key_of(temporary_secret_key);
        let next = self.get_path_to_leaf(public_key)?;

        self.make_blank_without_changes(&next, &new_public_key)?;

        self.update_art_with_secret_key(
            temporary_secret_key,
            &self.get_path_to_leaf(&new_public_key)?,
        )
        .map(|(root_key, mut changes)| {
            changes.change_type =
                BranchChangesType::MakeBlank(public_key.clone(), temporary_secret_key.clone());
            (root_key, changes)
        })
    }

    fn update_art_with_changes(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        let mut current_node = self.get_mut_root();
        for i in 0..changes.public_keys.len() - 1 {
            current_node.set_public_key(changes.public_keys[i].clone());
            current_node = current_node.get_mut_child(
                changes
                    .node_index
                    .get_path()?
                    .get(i)
                    .unwrap_or(&Direction::Right),
            )?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1].clone());

        Ok(())
    }

    fn update_art_with_changes_and_path(
        &mut self,
        changes: &BranchChanges<G>,
        path: &Vec<Direction>,
    ) -> Result<(), ARTError> {
        let mut current_node = self.get_mut_root();
        for (next, public_key) in path
            .iter()
            .zip(changes.public_keys[..changes.public_keys.len() - 1].iter())
        {
            current_node.set_public_key(public_key.clone());
            current_node = current_node.get_mut_child(next)?;
        }

        current_node.set_public_key(changes.public_keys[changes.public_keys.len() - 1].clone());

        Ok(())
    }

    fn get_node(&self, index: &NodeIndex) -> Result<&ARTNode<G>, ARTError> {
        let mut node = self.get_root();
        for direction in &index.get_path()? {
            node = node.get_child(direction)?;
        }

        Ok(node)
    }

    fn get_mut_node(&mut self, index: &NodeIndex) -> Result<&mut ARTNode<G>, ARTError> {
        let mut node = self.get_mut_root();
        for direction in &index.get_path()? {
            node = node.get_mut_child(direction)?;
        }

        Ok(node)
    }

    fn can_remove(&mut self, lambda: &G::ScalarField, public_key: &G) -> bool {
        let users_public_key = self.public_key_of(lambda);

        if users_public_key.eq(public_key) {
            return false;
        }

        let path_to_other = self.get_path_to_leaf(public_key).unwrap();
        let path_to_self = self.get_path_to_leaf(&users_public_key).unwrap();

        if path_to_other.len().abs_diff(path_to_self.len()) > 1 {
            return false;
        }

        for i in 0..(max(path_to_self.len(), path_to_other.len()) - 2) {
            if path_to_self[i] != path_to_other[i] {
                return false;
            }
        }

        true
    }

    fn remove_node(&mut self, path: &Vec<Direction>) -> Result<(), ARTError> {
        let mut target_node = self.get_mut_root();
        for direction in &path[..path.len() - 1] {
            target_node.weight -= 1;
            target_node = target_node.get_mut_child(direction)?;
        }

        target_node.shrink_to_other(path[path.len() - 1])?;

        Ok(())
    }

    fn remove_node_and_update_tree(
        &mut self,
        lambda: &G::ScalarField,
        public_key: &G,
    ) -> Result<(ARTRootKey<G>, BranchChanges<G>), ARTError> {
        if !self.can_remove(lambda, public_key) {
            return Err(ARTError::RemoveError);
        }

        let path = self.get_path_to_leaf(public_key)?;
        self.remove_node(&path)?;

        match self.update_art_with_secret_key(lambda, &path) {
            Ok((root_key, mut changes)) => {
                changes.change_type = BranchChangesType::RemoveNode(public_key.clone());

                Ok((root_key, changes))
            }
            Err(msg) => Err(msg),
        }
    }

    fn min_max_leaf_height(&self) -> Result<(u32, u32), ARTError> {
        let mut min_height = u32::MAX;
        let mut max_height = u32::MIN;
        let root = self.get_root();

        let mut path = vec![root.as_ref()];
        let mut next = vec![Direction::NoDirection];

        while !path.is_empty() {
            let last_node = path.last().unwrap();

            if last_node.is_leaf() {
                min_height = min(min_height, path.len() as u32);
                max_height = max(max_height, path.len() as u32);

                path.pop();
                next.pop();
            } else {
                match next.pop().unwrap() {
                    Direction::Left => {
                        path.push(last_node.get_right()?.as_ref());

                        next.push(Direction::Right);
                        next.push(Direction::NoDirection);
                    }
                    Direction::Right => {
                        path.pop();
                    }
                    Direction::NoDirection => {
                        path.push(last_node.get_left()?.as_ref());

                        next.push(Direction::Left);
                        next.push(Direction::NoDirection);
                    }
                }
            }
        }

        Ok((min_height, max_height))
    }

    fn get_disbalance(&self) -> Result<u32, ARTError> {
        let (min_height, max_height) = self.min_max_leaf_height()?;

        Ok(max_height - min_height)
    }

    fn update_public_art(&mut self, changes: &BranchChanges<G>) -> Result<(), ARTError> {
        match &changes.change_type {
            BranchChangesType::UpdateKey => self.update_art_with_changes(changes),
            BranchChangesType::AppendNode(node) => {
                self.append_node_without_changes(node.clone(), &changes.node_index.get_path()?)?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::MakeBlank(_, temporary_lambda) => {
                self.make_blank_without_changes(
                    &changes.node_index.get_path()?,
                    &self.public_key_of(temporary_lambda),
                )?;
                self.update_art_with_changes(changes)
            }
            BranchChangesType::RemoveNode(_) => Err(ARTError::RemoveError),
        }
    }
}
