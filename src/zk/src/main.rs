#![allow(non_snake_case)]
use zk::dh::dh_gadget_roundtrip;


fn main() {
    let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

    tracing_subscriber::fmt()
         .with_env_filter(log_level)
         .with_target(false)
         .init();

    dh_gadget_roundtrip().unwrap();
}