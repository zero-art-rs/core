use hibbe::{
    art::{ARTCiphertext, BranchChanges, ART},
    hybrid_encryption::HybridCiphertext,
    ibbe_del7::{self, UserIdentity},
};
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum CustomMessage {
    TextMessage(String),
    HibbeTextMessage(HybridCiphertext, BranchChanges),
    ChatInitMessage(ibbe_del7::PublicKey),
    SkRequest(PeerId),
    SkResponse(ibbe_del7::SecretKey, PeerId),
    ChatCreated(ART, Vec<ARTCiphertext>, Vec<UserIdentity<Vec<u8>>>),
    PingRequest(u32),
    PingReply(u32),
    Other,
}

impl CustomMessage {
    pub fn from_json(json: &str) -> Self {
        let deserialized: Self = serde_json::from_str(&json).unwrap();

        deserialized
    }

    pub fn serialize(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

// impl Into<Vec<u8>> for Message {
//     fn into(self) -> Vec<u8> {
//         self.serialize().into_bytes()
//     }
// }
