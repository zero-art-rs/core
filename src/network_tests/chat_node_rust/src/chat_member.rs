use crate::behavior::{message_id_fn, ChatBehaviour};
use crate::message::CustomMessage;
use crate::{message, TestHelper};

use libp2p::gossipsub::{Message, MessageId};
use libp2p::{gossipsub, PeerId, Swarm};
use relative_implementation::art::{ARTTrustedAgent, ARTUserAgent};
use relative_implementation::hybrid_encryption::HybridEncryption;
use relative_implementation::ibbe_del7::IBBEDel7;
use tracing_subscriber::fmt::format;

pub struct UserInterface {
    test_helper: TestHelper,
    hibbe: Option<HybridEncryption<Vec<u8>>>,
    peer_id: PeerId,
    // ibbe: Option<IBBEDel7>,
    // trusted_art_agent: Option<ARTTrustedAgent>,
    // art_agent: Option<ARTUserAgent>,
    // chat_users: Vec<PeerId>,
}

impl UserInterface {
    pub fn new(peer_id: &PeerId) -> Self {
        Self {
            test_helper: TestHelper::new_test_helper(peer_id.clone()),
            hibbe: None,
            peer_id: peer_id.clone(),
        }
    }

    pub fn process_sending_message(
        &mut self,
        message: &String,
        swarm: &mut Swarm<ChatBehaviour>,
        topic: &gossipsub::IdentTopic,
    ) {
        if message.len() == 0 {
            // Do nothing
        } else if message[0..1] != String::from("/") {
            self.send_line(swarm, topic, message);
        } else {
            let words: Vec<&str> = message.split_whitespace().collect();
            match words[0] {
                "/ping" => {
                    self.test_helper.have_send_ping = true;
                    self.ping_action(swarm, topic)
                }
                "/show" => {
                    println!("/show..");
                    self.test_helper.show_test_results();
                }
                "/exit" => {
                    std::process::exit(0);
                }
                "/clear_table" => {
                    println!("/clear_table..");
                    self.test_helper.clear_data();
                }
                "/info" => {
                    println!("/Print info for node {}", swarm.local_peer_id().to_string());

                    println!("Set of connected peers:");
                    let mut number_of_connected_peers = 0;
                    for peer in swarm.connected_peers() {
                        println!(" - peer: {}", peer);
                        number_of_connected_peers += 1;
                    }
                    println!("Number of connected peers = {}", number_of_connected_peers);
                }
                "/init_chat" => {
                    let number_of_users = 60u32;

                    let ibbe = IBBEDel7::setup(number_of_users);
                    let mut art_trusted_agent =
                        ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());

                    // messenger_config.ibbe = Some(ibbe);
                    // messenger_config.trusted_art_agent = Some(art_trusted_agent);

                    // let (mut tree, ciphertexts, root_key) =
                    //     art_agent.compute_art_and_ciphertexts(&users);
                    // let tree_json = tree.serialise().unwrap();

                    // let message_to_send = String::from("/tree ") + &tree_json;
                    // send_line(swarm, &topic, &message_to_send, &mut messenger_config.hibbe);
                }
                _ => {}
            }
        }
    }

    pub fn process_receiving_message(
        &mut self,
        message: &Message,
        swarm: &mut Swarm<ChatBehaviour>,
        topic: &gossipsub::IdentTopic,
        source_id: &PeerId,
        message_id: &MessageId,
    ) {
        let received_message: String = String::from_utf8_lossy(&message.data).to_string();
        let received_message = message::CustomMessage::from_json(&received_message);

        let received_message = match received_message {
            CustomMessage::TextMessage(text) => text,
            _ => return,
        };

        if received_message[0..1] != String::from("/") {
            // println!(
            //     "[{msg_source}] by {source_id}: '{received_message}'",
            //     msg_source = message.source.unwrap().to_string()
            // );
            println!(
                "From [{msg_source}]: - seq_n: [{seq_n}], id: [{msg_id}] - '{received_message}' - '{msg_topic}'.",
                msg_source = message.source.unwrap().to_string(),
                seq_n = message.sequence_number.unwrap().to_string(),
                msg_id = message_id_fn(message).to_string().as_str(),
                msg_topic = message.topic.as_str(),
            );
        } else {
            let words: Vec<&str> = received_message.split_whitespace().collect();

            match words[0] {
                "/ping_request" => {
                    if words.len() >= 2 {
                        let message_to_send =
                            format!("/ping_reply {} {}", message.source.unwrap(), words[1]);
                        self.send_line(swarm, topic, &message_to_send);

                        println!(
                            "Replay [{msg_source}] - seq_n: [{seq_n}] - msg: [{received_message}] - topic: [{msg_topic}] - id: [[{msg_id}]]",
                            msg_source = message.source.unwrap().to_string(),
                            seq_n = message.sequence_number.unwrap().to_string(),
                            msg_topic = message.topic.as_str(),
                            msg_id = message_id_fn(message).to_string().as_str(),
                        );
                    }
                }
                "/ping_reply" => {
                    if self.test_helper.have_send_ping && words.len() >= 2 {
                        let ping_counter = words[2].parse().unwrap();
                        if self.test_helper.have_send_ping {
                            self.test_helper.append_ping_result(
                                &message.source.unwrap().to_string(),
                                ping_counter,
                            );
                        }

                        println!(
                            "Ping reply from peer {msg_source}, with pay-load {ping_counter}",
                            msg_source = message.source.unwrap().to_string()
                        );
                    }
                }
                // "/tree" => {
                //     ARTUserAgent::f
                // }
                _ => {}
            }
        }
    }

    pub fn send_line(
        &mut self,
        swarm: &mut Swarm<ChatBehaviour>,
        topic: &gossipsub::IdentTopic,
        line: &String,
    ) {
        let text = match &mut self.hibbe {
            Some(schemma) => {
                let encryption = schemma.encrypt(line.clone());
                // let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
                serde_json::to_string(&encryption).unwrap()
            }
            None => line.clone(),
        };

        let outgoing_message = CustomMessage::TextMessage(text);

        if let Err(e) = swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic.clone(), outgoing_message.serialize())
        {
            println!("Publish error: {e:?}");
        }
    }

    pub fn ping_action(&mut self, swarm: &mut Swarm<ChatBehaviour>, topic: &gossipsub::IdentTopic) {
        self.test_helper.start_ping_test();

        let mut message_to_send: String = String::from("/ping_request ");
        message_to_send.push_str(self.test_helper.ping_counter.to_string().as_str());

        self.send_line(swarm, &topic, &message_to_send);
        self.test_helper.ping_counter += 1;
    }
}
