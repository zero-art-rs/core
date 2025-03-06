use std::time::Instant;
use rand::Rng;
use crate::ibbe_del7::IBBEDel7;
use super::*;

pub struct SpeedMetrics {}

impl SpeedMetrics {
    pub fn test_all(number_of_iterations: u128) {
        SpeedMetrics::test_complex(10, number_of_iterations);
        SpeedMetrics::test_complex(100, number_of_iterations);
        SpeedMetrics::test_complex(1000, number_of_iterations);
        SpeedMetrics::test_complex(10000, 10);
    }

    fn test_setup(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;

        for _ in 0..number_of_iterations {
            let start_time: Instant = Instant::now();
            _ = IBBEDel7::run_setup(number_of_users);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!("test_setup {number_of_users} users: {} ms", avg_duration as f64 / 1000000.0);
    }

    fn test_extract(number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let number_of_users = 10u32;

        let (msk, pk) = IBBEDel7::run_setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = rng.gen_range(0..number_of_users);

            let start_time: Instant = Instant::now();
            _ = IBBEDel7::extract(&msk, user_id);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!("test_extract: {} ms", avg_duration as f64 / 1000000.0);
    }

    fn test_encrypt(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let set_of_users: Vec<u32> = (0..number_of_users).collect();

        let (msk, pk) = IBBEDel7::run_setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = rng.gen_range(0..number_of_users);
            let sk_id = IBBEDel7::extract(&msk, user_id);

            let start_time: Instant = Instant::now();
            _ = IBBEDel7::encrypt(&set_of_users, &pk);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!("test_encrypt {number_of_users} users: {} ms", avg_duration as f64 / 1000000.0);
    }

    fn test_decrypt(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let set_of_users: Vec<u32> = (0..number_of_users).collect();

        let (msk, pk) = IBBEDel7::run_setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = rng.gen_range(0..number_of_users);
            let sk_id = IBBEDel7::extract(&msk, user_id);
            let (hdr, _) = IBBEDel7::encrypt(&set_of_users, &pk);

            let start_time: Instant = Instant::now();
            _ = IBBEDel7::decrypt(&set_of_users, user_id, &sk_id, &hdr, &pk);
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!("test_decrypt {number_of_users} users: {} ms", avg_duration as f64 / 1000000.0);
    }

    fn test_complex(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time_setup = 0u128;
        let mut total_execution_time_extract = 0u128;
        let mut total_execution_time_encrypt = 0u128;
        let mut total_execution_time_decrypt = 0u128;

        let mut rng = rand::thread_rng();
        let set_of_users: Vec<u32> = (0..number_of_users).collect();

        for _ in 0..number_of_iterations {
            let start_time: Instant = Instant::now();
            let (msk, pk) = IBBEDel7::run_setup(number_of_users);
            let end_time: Instant = Instant::now();
            total_execution_time_setup += end_time.duration_since(start_time).as_nanos();

            let user_id = rng.gen_range(0..number_of_users);

            let start_time: Instant = Instant::now();
            let sk_id = IBBEDel7::extract(&msk, user_id);
            let end_time: Instant = Instant::now();
            total_execution_time_extract += end_time.duration_since(start_time).as_nanos();

            let start_time: Instant = Instant::now();
            let (hdr, key) = IBBEDel7::encrypt(&set_of_users, &pk);
            let end_time: Instant = Instant::now();
            total_execution_time_encrypt += end_time.duration_since(start_time).as_nanos();

            let start_time: Instant = Instant::now();
            let decrypted_key = IBBEDel7::decrypt(&set_of_users, user_id, &sk_id, &hdr, &pk);
            let end_time: Instant = Instant::now();
            total_execution_time_decrypt += end_time.duration_since(start_time).as_nanos();

            assert!(decrypted_key.eq(&key)) // simple correctness test
        }

        println!();
        println!("test_setup {number_of_users} users, {number_of_iterations} iterations: {} ms", (total_execution_time_setup as f64 / number_of_iterations as f64) / 1000000.0);
        println!("test_extract {number_of_users} users, {number_of_iterations} iterations: {} ms", (total_execution_time_extract as f64 / number_of_iterations as f64) / 1000000.0);
        println!("test_encrypt {number_of_users} users, {number_of_iterations} iterations: {} ms", (total_execution_time_encrypt as f64 / number_of_iterations as f64) / 1000000.0);
        println!("test_decrypt {number_of_users} users, {number_of_iterations} iterations: {} ms", (total_execution_time_decrypt as f64 / number_of_iterations as f64) / 1000000.0);
    }

}