// Hybrid of IBBBEDel7 and Asymmetric Ratchet Tree

use ark_bn254::{G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField};
use serde::{Deserialize, Serialize};
use crate::art::ARTUserAgent;
use crate::{
    art::{ART, BranchChanges},
    ibbe_del7::{EncryptionKey, Header, IBBEDel7, SecretKey, UserIdentity},
    tools::{self, ark_de, ark_se},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridCiphertext {
    ibbe_hdr: Header,
    ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub struct HybridEncryption<T> {
    art_agent: ARTUserAgent,
    ibbe: IBBEDel7,
    users: Vec<UserIdentity<T>>,
    user_identity: UserIdentity<T>,
    stk: Vec<u8>,
    ibbe_sk: SecretKey,
}

impl<T: Into<Vec<u8>> + Clone + PartialEq> HybridEncryption<T> {
    pub fn new(
        ibbe: IBBEDel7,
        art_agent: ARTUserAgent,
        users: Vec<UserIdentity<T>>,
        user_identity: UserIdentity<T>,
        ibbe_sk: SecretKey,
    ) -> Self {
        let mut ikm = vec![0; 32];
        ikm.append(&mut art_agent.get_root_key().key.to_string().into_bytes());
        let info = "compute stage key".as_bytes();
        let stk = tools::hkdf(&ikm, None, info);

        Self {
            art_agent,
            ibbe,
            users,
            user_identity,
            stk,
            ibbe_sk,
        }
    }

    pub fn update_stage_key(&mut self) {
        let mut ikm = self.stk.clone();
        ikm.append(&mut self.art_agent.get_root_key().key.to_string().into_bytes());
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
        let tree_key = self.art_agent.get_root_key().key.clone();

        let mut ikm = ibbe_key.key.to_string().as_bytes().to_vec();
        ikm.append(&mut tree_key.to_string().into_bytes());
        let encryption_key = self.combine_keys(ibbe_key, tree_key);

        let ciphertext = tools::encrypt_aes(encryption_key, message).unwrap();

        let (root_key, changes) = self.art_agent.update_key().unwrap();
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
        let tree_key = self.art_agent.get_root_key().key.clone();
        let decryption_key = self.combine_keys(ibbe_key, tree_key);

        let plaintext = tools::decrypt_aes(decryption_key, cipher.ciphertext).unwrap();

        _ = self.art_agent.update_branch(&changes);

        plaintext
    }
}
