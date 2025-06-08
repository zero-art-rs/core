#![allow(non_snake_case)]
use zk::{art_roundtrip, dh::dh_gadget_roundtrip};
use std::thread;


fn main() {
    let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

    tracing_subscriber::fmt()
         .with_env_filter(log_level)
         .with_target(false)
         .init();

    /*let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(thread::spawn(|| {
            dh_gadget_roundtrip(2).unwrap();
        }));
    }
    for handle in handles {
        handle.join().unwrap();
    }*/
    art_roundtrip(10).unwrap();
}