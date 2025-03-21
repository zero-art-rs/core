use libp2p::identity::Keypair;
use libp2p::{
    gossipsub::{self, Message, MessageId},
    mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm,
};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Duration;
use tokio::{io, io::AsyncBufReadExt, select};

#[derive(NetworkBehaviour)]
pub struct ChatBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub fn message_id_fn(message: &gossipsub::Message) -> MessageId {
    let mut s = DefaultHasher::new();
    message.data.hash(&mut s);
    message.source.hash(&mut s);
    message.topic.hash(&mut s);
    message.sequence_number.hash(&mut s);

    gossipsub::MessageId::from(s.finish().to_string())
}
