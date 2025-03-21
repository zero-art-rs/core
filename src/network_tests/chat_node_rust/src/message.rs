use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum CustomMessage {
    TextMessage(String),
    TreeMessage,
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
