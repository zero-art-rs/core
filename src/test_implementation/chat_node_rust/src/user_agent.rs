use std::option::Option;

use crate::behavior::{message_id_fn, ChatBehaviour};
use crate::message::CustomMessage;
use crate::{message, TestHelper};
use futures::stream::{FusedStream, SelectNextSome};
use futures::StreamExt;

use libp2p::gossipsub::{Message, MessageId};
use libp2p::{gossipsub, PeerId, Swarm};
use relative_implementation::art::{
    ARTCiphertext, ARTTrustedAgent, ARTUserAgent, BranchChanges, ART,
};
use relative_implementation::hybrid_encryption::{HybridCiphertext, HybridEncryption};
use relative_implementation::ibbe_del7::{self, IBBEDel7, UserIdentity};

pub struct UserInterface {
    test_helper: TestHelper,
    hibbe: Option<HybridEncryption<Vec<u8>>>,
    peer_id: PeerId,
    pub swarm: Swarm<ChatBehaviour>,
    pk: Option<ibbe_del7::PublicKey>,
    ibbe: Option<IBBEDel7>,
    trusted_art_agent: Option<ARTTrustedAgent>,
    sk_id: Option<ibbe_del7::SecretKey>,
    art_agent: Option<ARTUserAgent>,
    chat_users: Vec<UserIdentity<Vec<u8>>>,
    default_number_of_users: u32,
}

impl UserInterface {
    pub fn new(swarm: Swarm<ChatBehaviour>) -> Self {
        let peer_id = swarm.local_peer_id();

        Self {
            test_helper: TestHelper::new_test_helper(peer_id.clone()),
            hibbe: None,
            peer_id: peer_id.clone(),
            swarm,
            pk: None,
            ibbe: None,
            trusted_art_agent: None,
            sk_id: None,
            art_agent: None,
            chat_users: vec![],
            default_number_of_users: 60u32,
        }
    }

    pub fn select_next_some(&mut self) -> SelectNextSome<'_, Swarm<ChatBehaviour>> {
        self.swarm.select_next_some()
    }

    pub fn process_sending_message(&mut self, line: &str, topic: &gossipsub::IdentTopic) {
        if line.len() == 0 {
            // Do nothing
        } else if line[0..1] != String::from("/") {
            self.send_line(topic, line);
        } else {
            let words: Vec<&str> = line.split_whitespace().collect();
            match words[0] {
                "/help" => {
                    println!("\nThere are next commands:");
                    println!("/ping - send ping request,");
                    println!("/show - show current ping request results,");
                    println!("/send_clear - send message in clear, without encryption,");
                    println!("/send_enc - send encrypted message,");
                    println!("/exit - end the program execution,");
                    println!("/clear_table - clears the table of ping request results,");
                    println!("/info - print info about the node,");
                    println!("/init_chat - create public key for chat (trusted setup),");
                    println!("/finalise_chat - create tree and a set of ciphertexts for available users, to start hibbe encryption,");
                    println!();
                },
                "/ping" => {
                    self.test_helper.have_send_ping = true;
                    self.ping_action(topic)
                }
                "/show" => {
                    println!("/show..");
                    self.test_helper.show_test_results();
                }
                "/send_clear" => {
                    match line.strip_prefix("/send_clear ") {
                        Some(msg) => {self.send_clear_message(topic, msg)},
                        None => println!("No message provided"),
                    }
                }
                "/send_enc" => {
                    match line.strip_prefix("/send_enc ") {
                        Some(msg) => {self.send_encrypted_message(topic, msg)},
                        None => println!("No message provided"),
                    }
                }
                "/exit" => {
                    std::process::exit(0);
                }
                "/clear_table" => {
                    println!("/clear_table..");
                    self.test_helper.clear_data();
                }
                "/info" => {
                    println!(
                        "/Print info for node {}",
                        self.swarm.local_peer_id().to_string()
                    );

                    println!("Set of connected peers:");
                    let mut number_of_connected_peers = 0;
                    for peer in self.swarm.connected_peers() {
                        println!(" - peer: {}", peer);
                        number_of_connected_peers += 1;
                    }
                    println!("Number of connected peers = {}", number_of_connected_peers);
                }
                "/init_chat" => {
                    let msg = &self.init_chat();
                    self.send_message(topic, &msg);
                },
                "/finalise_chat" => {
                    let fin_msg = self.finalise_chat();

                    println!("Finalisation for {} members", self.chat_users.len());
                    match fin_msg {
                        Ok(msg) => self.send_message(topic, &msg),
                        Err(e) => println!("{}", e),
                    }
                }
                _ => {}
            }
        }
    }

    pub fn init_chat(&mut self) -> CustomMessage {
        let ibbe = IBBEDel7::setup(self.default_number_of_users);
        self.pk = Some(ibbe.pk.clone());
        let art_trusted_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());

        self.ibbe = Some(ibbe);
        self.trusted_art_agent = Some(art_trusted_agent);

        CustomMessage::ChatInitMessage(self.pk.clone().unwrap())
    }

    pub fn finalise_chat(&mut self) -> Result<CustomMessage, String> {
        match &mut self.trusted_art_agent {
            Some(trusted_art) => {
                let (mut tree, ciphertexts, root_key) =
                    trusted_art.compute_art_and_ciphertexts(&self.chat_users);

                Ok(CustomMessage::ChatCreated(
                    tree,
                    ciphertexts,
                    self.chat_users.clone(),
                ))
            }
            None => Err("trusted art is not initialized".to_string()),
        }
    }

    pub fn print_message(&self, message: &Message, message_text: &str) {
        println!(
            "[{msg_topic}::{msg_source}] ({seq_n}, {msg_id}): '{message_text}'.",
            msg_source = message.source.unwrap().to_string(),
            seq_n = message.sequence_number.unwrap().to_string(),
            msg_id = message_id_fn(message).to_string().as_str(),
            msg_topic = message.topic.as_str(),
        );
    }

    pub fn process_receiving_message(
        &mut self,
        message: &Message,
        topic: &gossipsub::IdentTopic,
        source_id: &PeerId,
        message_id: &MessageId,
    ) {
        let received_message: String = String::from_utf8_lossy(&message.data).to_string();
        let received_message = CustomMessage::from_json(&received_message);

        match received_message {
            CustomMessage::TextMessage(text) => {
                self.print_message(message, &text);
            }
            CustomMessage::HibbeTextMessage(ciphertext, changes) => {
                let decrypted_message = self.decrypt(ciphertext, &changes);
                match decrypted_message {
                    Ok(decrypted_message) => {
                        self.print_message(message, &format!("<<{}>>", &decrypted_message))
                    }
                    Err(e) => println!("Failed to decrypt message: {}", e),
                }
            }
            CustomMessage::ChatInitMessage(pk) => {
                self.pk = Some(pk.clone());
                self.ibbe = Some(IBBEDel7::from(pk));
                println!("Received public key");
                self.send_message(topic, &CustomMessage::SkRequest(message.source.unwrap()));
            }
            CustomMessage::PingRequest(ping_seq) => {
                self.send_message(topic, &CustomMessage::PingReply(ping_seq));
                self.print_message(message, &format!("Ping seq: {}", ping_seq));
            }
            CustomMessage::PingReply(ping_seq) => {
                if self.test_helper.have_send_ping {
                    self.test_helper.append_ping_result(
                        &message.source.unwrap().to_string(),
                        ping_seq as usize,
                    );

                    println!(
                        "Ping reply from peer {msg_source}, with pay-load {ping_seq}",
                        msg_source = message.source.unwrap().to_string()
                    );
                }
            }
            CustomMessage::SkRequest(peer_id) => {
                if self.peer_id == peer_id {
                    let uid = UserIdentity::new(message.source.unwrap().to_bytes());

                    self.chat_users.push(uid.clone());

                    match self.extract_key(&uid) {
                        Ok(sk) => {
                            self.send_message(
                                topic,
                                &CustomMessage::SkResponse(sk, message.source.unwrap()),
                            );
                        }
                        Err(e) => println!("Error extracting key: {}", e),
                    };
                }
            }
            CustomMessage::SkResponse(sk, peer_id) => {
                if self.peer_id == peer_id {
                    self.sk_id = Some(sk);
                    println!("Received private key from peer {}", message.source.unwrap());
                }
            }
            CustomMessage::ChatCreated(art, ciphertexts, members) => {
                if ciphertexts.len() != members.len() {
                    println!("Wrong number of ciphertexts");
                    return;
                }

                let user_identity = UserIdentity::new(self.peer_id.to_bytes());
                for i in 0..ciphertexts.len() {
                    if user_identity == members[i] {
                        let mut user1_agent =
                            ARTUserAgent::new(art, ciphertexts[i], self.sk_id.unwrap());
                        let hibbe = HybridEncryption::new(
                            self.ibbe.clone().unwrap(),
                            user1_agent,
                            members.clone(),
                            user_identity.clone(),
                            self.sk_id.unwrap(),
                        );

                        self.hibbe = Some(hibbe);

                        println!("Chat is set up");
                        return;
                    }
                }

                println!("Can't create chat: wrong user_identity");
            }
            _ => println!("Received unsupported message {:?}", received_message),
        };
    }

    pub fn extract_key(
        &mut self,
        uid: &UserIdentity<Vec<u8>>,
    ) -> Result<ibbe_del7::SecretKey, String> {
        match &self.ibbe {
            Some(ibbe) => ibbe.extract(uid),
            None => Err("No ibbe instance created".to_string()),
        }
    }

    pub fn send_line(&mut self, topic: &gossipsub::IdentTopic, line: &str) {
        match &self.hibbe {
            Some(_) => self.send_encrypted_message(topic, line),
            None => self.send_clear_message(topic, line),
        };
    }

    pub fn send_encrypted_message(&mut self, topic: &gossipsub::IdentTopic, line: &str) {
        let line_encryption = self.encrypt(line);
        match line_encryption {
            Ok((ciphertext, changes)) =>
                self.send_message(topic, &CustomMessage::HibbeTextMessage(ciphertext, changes)),
            Err(e) => println!("Failed to encrypt message: {}", e),
        }

    }

    pub fn send_clear_message(&mut self, topic: &gossipsub::IdentTopic, line: &str) {
        self.send_message(topic, &CustomMessage::TextMessage(String::from(line)));
    }

    pub fn encrypt(
        &mut self,
        line: &str,
    ) -> Result<(HybridCiphertext, BranchChanges), String> {
        match &mut self.hibbe {
            Some(hibbe) => Ok(hibbe.encrypt(String::from(line))),
            None => Err("No hibbe instance created".to_string()),
        }
    }

    pub fn decrypt(
        &mut self,
        cipher: HybridCiphertext,
        changes: &BranchChanges,
    ) -> Result<String, String> {
        match &mut self.hibbe {
            Some(hibbe) => {
                let plaintext = hibbe.decrypt(cipher, changes);
                Ok(plaintext)
            }
            None => Err("No hibbe instance created".to_string()),
        }
    }

    pub fn send_message(&mut self, topic: &gossipsub::IdentTopic, message: &CustomMessage) {
        if let Err(e) = self
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), message.serialize())
        {
            println!("Publish error: {e:?}");
        }
    }

    pub fn ping_action(&mut self, topic: &gossipsub::IdentTopic) {
        self.test_helper.start_ping_test();

        let mut message_to_send: String = String::from("/ping_request ");
        message_to_send.push_str(self.test_helper.ping_counter.to_string().as_str());

        // self.send_line(&topic, &message_to_send);
        self.send_message(
            topic,
            &CustomMessage::PingRequest(self.test_helper.ping_counter),
        );
        self.test_helper.ping_counter += 1;
    }
}
