use futures::stream::StreamExt;
use libp2p::gossipsub::{Message, MessageId};
use libp2p::{
    gossipsub, mdns, noise,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, yamux, PeerId, Swarm,
};
use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    error::Error,
    hash::{Hash, Hasher},
    thread,
    time::Duration,
    time::SystemTime,
    vec,
};
use tokio::{io, io::AsyncBufReadExt, select};
use tracing_subscriber::EnvFilter;

// We create a custom network behaviour that combines Gossipsub and Mdns.
#[derive(NetworkBehaviour)]
struct MyBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

struct TestHelper {
    have_send_ping: bool,
    tests_start_time: SystemTime,
    ping_start_time: Vec<SystemTime>,
    local_peer_id: PeerId,
    time_table: Vec<HashMap<String, u128>>,
    ping_size_records: Vec<u32>,
    average_time_records: Vec<f64>,
    ping_counter: u64,
}

impl TestHelper {
    fn new_test_helper(peer_id: PeerId) -> TestHelper {
        TestHelper {
            have_send_ping: false,
            tests_start_time: SystemTime::now(),
            ping_start_time: Vec::new(),
            local_peer_id: peer_id,
            time_table: Vec::new(),
            ping_size_records: Vec::new(),
            average_time_records: Vec::new(),
            ping_counter: 0,
        }
    }

    fn clear_data(&mut self) {
        self.have_send_ping = false;
        self.tests_start_time = SystemTime::now();
        self.ping_start_time = Vec::new();
        self.time_table = Vec::new();
        self.ping_size_records = Vec::new();
        self.average_time_records = Vec::new();
        self.ping_counter = 0;
    }

    fn start_ping_test(&mut self) {
        self.ping_start_time.push(SystemTime::now());
        self.time_table.push(HashMap::new());
    }

    fn append_ping_result(&mut self, peer_id: &String, ping_id: usize) {
        let elapsed = self.ping_start_time[ping_id].elapsed().unwrap().as_millis();

        while self.time_table.len() <= ping_id {
            self.time_table.push(HashMap::new());
        };

        match self.time_table[ping_id].get(&peer_id.clone()) {
            Some(peer_id) => {}
            None => {
                self.time_table[ping_id].insert(peer_id.clone(), elapsed);
            }
        }
    }

    fn show_test_results(&mut self) {
        let mut total_average_time = 0f64;
        let mut total_average_ping_size = 0;
        let mut record_number = 0;
        for (i, ping_record) in self.time_table.iter().enumerate() {
            let mut average_time = 0f64;
            for receive_time in ping_record.values() {
                average_time = average_time + (receive_time.clone() as f64);
            }
            average_time = average_time / ping_record.len() as f64;
            average_time = average_time / 2f64;

            if average_time.is_nan() {
                println!("Average time is NaN");
            } else {
                println!(
                    "Average time for ping test {i}: {average_time} ms, where was received {} ping replays",
                    ping_record.len()
                );

                total_average_ping_size += ping_record.len();
                total_average_time += average_time;

                record_number += 1;
            }

        }

        println!(
            "Total average time for ping request: {} ms, while on average, received {} ping replays",
            total_average_time  / record_number as f64,
            total_average_ping_size as f64 / record_number as f64
        );
    }
}

fn send_line(swarm: &mut Swarm<MyBehaviour>, topic: &gossipsub::IdentTopic, line: &String) {
    if let Err(e) = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), line.as_bytes())
    {
        println!("Publish error: {e:?}");
    }
}

fn ping_action(th: &mut TestHelper, swarm: &mut Swarm<MyBehaviour>, topic: &gossipsub::IdentTopic) {
    th.start_ping_test();

    let mut message_to_send: String = String::from("/ping_request ");
    message_to_send.push_str(th.ping_counter.to_string().as_str());

    send_line(swarm, &topic, &message_to_send);
    th.ping_counter += 1;
}

fn process_sending_message(
    s: &String,
    th: &mut TestHelper,
    swarm: &mut Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
) {
    if s.len() == 0 {
        // Do nothing
    } else if s[0..1] != String::from("/") {
        send_line(swarm, &topic, s);
    } else {
        let words: Vec<&str> = s.split_whitespace().collect();
        match words[0] {
            "/ping" => {
                th.have_send_ping = true;
                ping_action(
                    th,
                    swarm,
                    &topic,
                )
            }
            "/show" => {
                println!("/show..");
                th.show_test_results();
            }
            "/exit" => {
                std::process::exit(0);
            }
            "/clear_table" => {
                println!("/clear_table..");
                th.clear_data();
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
            _ => {}
        }
    }
}

fn process_receiving_message(
    message: &Message,
    th: &mut TestHelper,
    swarm: &mut Swarm<MyBehaviour>,
    topic: &gossipsub::IdentTopic,
    source_id: &PeerId,
    message_id: &MessageId,
) {
    let received_message: String = String::from_utf8_lossy(&message.data).to_string();

    if received_message[0..1] != String::from("/") {
        // println!(
        //     "[{msg_source}] by {source_id}: '{received_message}'",
        //     msg_source = message.source.unwrap().to_string()
        // );
        println!(
            "From [{msg_source}]: - seq_n: [{seq_n}], id: [{msg_id}] - '{received_message}' - '{msg_topic}'.",
            msg_source = message.source.unwrap().to_string(),
            seq_n = message.sequence_number.unwrap().to_string(),
            msg_topic = message.topic.as_str(),
            msg_id = message_id_fn(message).to_string().as_str(),
        );
    } else {
        let words: Vec<&str> = received_message.split_whitespace().collect();

        match words[0] {
            "/ping_request" =>  {
                if words.len() >= 2 {
                    send_line(
                        swarm,
                        &topic,
                        &(String::from("/ping_reply ")
                            + &String::from(message.source.unwrap().to_string().as_str())
                            + &String::from(" ")
                            + &String::from(words[1])),
                    );

                    println!(
                        "Replay [{msg_source}] - seq_n: [{seq_n}] - msg: [{received_message}] - topic: [{msg_topic}] - id: [[{msg_id}]]",
                        msg_source = message.source.unwrap().to_string(),
                        seq_n = message.sequence_number.unwrap().to_string(),
                        msg_topic = message.topic.as_str(),
                        msg_id = message_id_fn(message).to_string().as_str(),
                    );
                }
            },
            "/ping_reply" => {
                if th.have_send_ping && words.len() >= 2 {
                    let ping_counter = words[2].parse().unwrap();
                    if th.have_send_ping {
                        th.append_ping_result(&message.source.unwrap().to_string(), ping_counter);
                    }

                    println!("Ping reply from peer {msg_source}, with pay-load {ping_counter}", msg_source = message.source.unwrap().to_string());
                }
            }
            _ => {}
        }
    }
}

// To content-address message, we can take the hash of message and use it as an ID.
fn message_id_fn (message: &gossipsub::Message) -> MessageId {
    let mut s = DefaultHasher::new();
    message.data.hash(&mut s);
    message.source.hash(&mut s);
    message.topic.hash(&mut s);

    gossipsub::MessageId::from(s.finish().to_string())
    // gossipsub::MessageId::from(message.sequence_number.unwrap().to_string())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init();

    let mut swarm = libp2p::SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_quic()
        .with_behaviour(|key| {

            // Set a custom gossipsub configuration
            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1)) // This is set to aid debugging by not cluttering the log space
                .validation_mode(gossipsub::ValidationMode::Strict) // This sets the kind of message validation. The default is Strict (enforce message
                // signing)
                .message_id_fn(message_id_fn) // content-address messages. No two messages of the same content will be propagated.
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?; // Temporary hack because `build` does not return a proper `std::error::Error`.

            // build a gossipsub network behaviour
            let gossipsub = gossipsub::Behaviour::new(
                gossipsub::MessageAuthenticity::Signed(key.clone()),
                gossipsub_config,
            )?;

            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            Ok(MyBehaviour { gossipsub, mdns })
        })?
        .build();

    // Create a Gossipsub topic
    let topic = gossipsub::IdentTopic::new("test-net");
    // subscribes to our topic
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    // Read full lines from stdin
    let mut stdin = io::BufReader::new(io::stdin()).lines();

    // Listen on all interfaces and whatever port the OS assigns
    swarm.listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse()?)?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    // if let Some(addr) = std::env::args().nth(0) {
    //     swarm.listen_on( addr.parse()?)?;
    // }

    println!("Start messaging..");
    println!("Local peer id: {}", swarm.local_peer_id().to_string());

    let mut th: TestHelper = TestHelper::new_test_helper(swarm.local_peer_id().clone());

    // Kick it off
    loop {
        select! {
            Ok(Some(line)) = stdin.next_line() => {
                process_sending_message(
                    &line.to_string(),
                    &mut th,
                    &mut swarm,
                    &topic,
                );
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discovered a new peer: {peer_id}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                    for (peer_id, _multiaddr) in list {
                        println!("mDNS discover peer has expired: {peer_id}");
                        swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                    }
                },
                SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: id,
                    message,
                })) => {
                    process_receiving_message(
                        &message,
                        &mut th,
                        &mut swarm,
                        &topic,
                        &peer_id,
                        &id
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
