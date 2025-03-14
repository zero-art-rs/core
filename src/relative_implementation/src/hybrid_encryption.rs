// Hybrid of IBBBEDel7 and Asymmetric Ratchet Tree

use ark_bn254::{
    Bn254, Config, Fq12Config, G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField,
    fr::FrConfig,
};
use ark_ec::bn::{Bn, G1Projective, G2Projective};

use crate::art::{BranchChanges, Direction};
use crate::ibbe_del7::{EncryptionKey, Header};
use crate::{
    art::{ART, ARTAgent},
    ibbe_del7::{IBBEDel7, MasterSecretKey, PublicKey, SecretKey, UserIdentity},
    tools,
};

#[derive(Debug, Clone)]
pub struct HybridCiphertext {
    ibbe_hdr: Header,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct HybridEncryption<T> {
    tree: ART,
    ibbe: IBBEDel7,
    users: Vec<UserIdentity<T>>,
    user_identity: UserIdentity<T>,
    stk: Vec<u8>,
    ibbe_sk: SecretKey,
}

impl<T: Into<Vec<u8>> + Clone + PartialEq> HybridEncryption<T> {
    pub fn new(
        ibbe: IBBEDel7,
        tree: ART,
        users: Vec<UserIdentity<T>>,
        user_identity: UserIdentity<T>,
        ibbe_sk: SecretKey,
    ) -> Self {
        let mut ikm = vec![0; 32];
        ikm.append(&mut tree.root_key.unwrap().key.to_string().into_bytes());
        let info = "compute stage key".as_bytes();
        let stk = tools::hkdf(&ikm, None, info);

        Self {
            tree,
            ibbe,
            users,
            user_identity,
            stk,
            ibbe_sk,
        }
    }

    pub fn update_stage_key(&mut self) {
        let mut ikm = self.stk.clone();
        ikm.append(&mut self.tree.root_key.unwrap().key.to_string().into_bytes());
        let info = "update stage key".as_bytes();
        self.stk = tools::hkdf(&ikm, None, info);
    }

    fn combine_keys(&self, ibbe_key: EncryptionKey, tree_key: ScalarField) -> Vec<u8> {
        let mut ikm = ibbe_key.key.to_string().as_bytes().to_vec();
        ikm.append(&mut tree_key.to_string().into_bytes());

        let info = "ibbe and tree keys combination".as_bytes();
        tools::hkdf(&ikm, None, info)
    }
    pub fn encrypt(&mut self, message: String) -> (HybridCiphertext, BranchChanges) {
        let (hdr, ibbe_key) = self.ibbe.encrypt(&self.users);
        let tree_key = self.tree.root_key.unwrap().key.clone();

        let mut ikm = ibbe_key.key.to_string().as_bytes().to_vec();
        ikm.append(&mut tree_key.to_string().into_bytes());
        let encryption_key = self.combine_keys(ibbe_key, tree_key);

        let ciphertext = tools::encrypt_aes(encryption_key, message).unwrap();

        let (root_key, changes) = self.tree.update_key().unwrap();
        self.update_stage_key();

        (
            HybridCiphertext {
                ibbe_hdr: hdr,
                ciphertext,
            },
            changes,
        )
    }

    pub fn decrypt(&mut self, cipher: HybridCiphertext, changes: &BranchChanges) -> String {
        let ibbe_key = self.ibbe.decrypt(
            &self.users,
            &self.user_identity,
            &self.ibbe_sk,
            &cipher.ibbe_hdr,
        );
        let tree_key = self.tree.root_key.unwrap().key.clone();
        let decryption_key = self.combine_keys(ibbe_key, tree_key);

        let plaintext = tools::decrypt_aes(decryption_key, cipher.ciphertext).unwrap();

        _ = self.tree.update_branch(&changes);

        plaintext
    }
}
