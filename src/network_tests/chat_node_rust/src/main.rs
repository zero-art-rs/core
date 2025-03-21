mod behavior;
mod chat_member;
mod message;
mod test_helper;
mod trusted_party;

use futures::stream::StreamExt;
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm,
};
use std::{
    env,
    error::Error,
    hash::{Hash, Hasher},
    time::Duration,
};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;

use crate::behavior::{message_id_fn, ChatBehaviour, ChatBehaviourEvent};
use crate::chat_member::UserInterface;
use crate::test_helper::TestHelper;

fn new_swarm() -> Result<Swarm<ChatBehaviour>, Box<dyn Error>> {
    let swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_behaviour(|key| {
            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                // .validation_mode(gossipsub::ValidationMode::Strict)
                // .published_message_ids_cache_time(Duration::from_secs(10))
                // .heartbeat_initial_delay(Duration::from_millis(100))
                // .duplicate_cache_time(Duration::from_secs(60 * 10))
                // .message_id_fn(behavior::message_id_fn)
                .build()?;

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;

            Ok(ChatBehaviour { gossipsub, mdns })
        })?
        .build();

    Ok(swarm)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    dbg!(args);

    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = new_swarm()?;

    let test_net_topic = gossipsub::IdentTopic::new("test-net");
    swarm.behaviour_mut().gossipsub.subscribe(&test_net_topic)?;

    let chat_topic = gossipsub::IdentTopic::new("test-chat");
    swarm.behaviour_mut().gossipsub.subscribe(&chat_topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    println!(
        "Start messaging with local PeerId: {}",
        swarm.local_peer_id().to_string()
    );

    let mut user_agent = UserInterface::new(swarm.local_peer_id());

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                user_agent.process_sending_message(
                    &line.to_string(),
                    &mut swarm,
                    &test_net_topic,
                );
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(ChatBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(ChatBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    user_agent.process_receiving_message(
                        &message,
                        &mut swarm,
                        &test_net_topic,
                        &peer_id,
                        &id,
                    )
                },
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {address}");
                }
                _ => {}
            }
        }
    }
}
