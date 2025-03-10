use super::*;
use crate::ibbe_del7::{IBBEDel7, UserIdentity};
use rand::Rng;
use std::time::Instant;

pub struct SpeedMetrics {}

impl SpeedMetrics {
    pub fn test_setup(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;

        for _ in 0..number_of_iterations {
            let start_time: Instant = Instant::now();
            _ = IBBEDel7::setup(number_of_users);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!(
            "test_setup {number_of_users} users: {} ms on average",
            avg_duration as f64 / 1000000.0
        );
    }

    pub fn test_extract(number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let number_of_users = 10u32;

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = rng.gen_range(0..number_of_users);

            let start_time: Instant = Instant::now();
            _ = ibbe.extract(&UserIdentity { id: user_id });
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!(
            "test_extract: {} ms on average",
            avg_duration as f64 / 1000000.0
        );
    }

    pub fn test_encrypt(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let users_id: Vec<u32> = (0..number_of_users).collect();
        let mut set_of_users = Vec::new();
        for id in users_id {
            set_of_users.push(UserIdentity { id });
        }

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = UserIdentity {
                id: rng.gen_range(0..number_of_users),
            };
            let sk_id = ibbe.extract(&user_id);

            let start_time: Instant = Instant::now();
            _ = ibbe.encrypt(&set_of_users);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!(
            "test_encrypt {number_of_users} users: {} ms on average",
            avg_duration as f64 / 1000000.0
        );
    }

    pub fn test_decrypt(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let users_id: Vec<u32> = (0..number_of_users).collect();
        let mut set_of_users = Vec::new();
        for id in users_id {
            set_of_users.push(UserIdentity { id });
        }

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = UserIdentity {
                id: rng.gen_range(0..number_of_users),
            };
            let sk_id = ibbe.extract(&user_id).unwrap();
            let (hdr, _) = ibbe.encrypt(&set_of_users);

            let start_time: Instant = Instant::now();
            _ = ibbe.decrypt(&set_of_users, &user_id, &sk_id, &hdr);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!(
            "test_decrypt {number_of_users} users: {} ms on average",
            avg_duration as f64 / 1000000.0
        );
    }

    pub fn test_complex(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time_setup = 0u128;
        let mut total_execution_time_extract = 0u128;
        let mut total_execution_time_encrypt = 0u128;
        let mut total_execution_time_decrypt = 0u128;

        let mut rng = rand::thread_rng();
        let users_id: Vec<u32> = (0..number_of_users).collect();
        let mut set_of_users = Vec::new();
        for id in users_id {
            set_of_users.push(UserIdentity { id });
        }

        for _ in 0..number_of_iterations {
            let start_time: Instant = Instant::now();
            let ibbe = IBBEDel7::setup(number_of_users);
            let end_time: Instant = Instant::now();
            total_execution_time_setup += end_time.duration_since(start_time).as_nanos();

            let user_id = UserIdentity {
                id: rng.gen_range(0..number_of_users),
            };

            let start_time: Instant = Instant::now();
            let sk_id = ibbe.extract(&user_id).unwrap();
            let end_time: Instant = Instant::now();
            total_execution_time_extract += end_time.duration_since(start_time).as_nanos();

            let start_time: Instant = Instant::now();
            let (hdr, key) = ibbe.encrypt(&set_of_users);
            let end_time: Instant = Instant::now();
            total_execution_time_encrypt += end_time.duration_since(start_time).as_nanos();

            let start_time: Instant = Instant::now();
            let decrypted_key = ibbe.decrypt(&set_of_users, &user_id, &sk_id, &hdr);
            let end_time: Instant = Instant::now();
            total_execution_time_decrypt += end_time.duration_since(start_time).as_nanos();
        }

        println!();
        println!(
            "test_setup {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_setup as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_extract {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_extract as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_encrypt {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_encrypt as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_decrypt {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_decrypt as f64 / number_of_iterations as f64) / 1000000.0
        );
    }

    pub fn test_signature_complex(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time_signature = 0u128;
        let mut total_execution_time_verification = 0u128;

        let mut rng = rand::thread_rng();
        let set_of_users: Vec<u32> = (0..number_of_users).collect();

        for _ in 0..number_of_iterations {
            let ibbe = IBBEDel7::setup(number_of_users);

            let user_id = UserIdentity {
                id: rng.gen_range(0..number_of_users),
            };
            let sk_id = ibbe.extract(&user_id).unwrap();

            let message: String = (0..100)
                .map(|_| char::from(rng.gen_range(32..127)))
                .collect();

            let start_time: Instant = Instant::now();
            let sigma = ibbe.sign(&message, &sk_id);
            let end_time: Instant = Instant::now();
            total_execution_time_signature += end_time.duration_since(start_time).as_nanos();

            let start_time: Instant = Instant::now();
            ibbe.verify(&message, &sigma, &user_id);
            let end_time: Instant = Instant::now();
            total_execution_time_verification += end_time.duration_since(start_time).as_nanos();
        }

        println!();
        println!(
            "test_signature {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_signature as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_verification {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_verification as f64 / number_of_iterations as f64) / 1000000.0
        );
    }
}
