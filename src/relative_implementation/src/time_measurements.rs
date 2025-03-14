use super::*;
use crate::art::{ARTAgent, ART};
use crate::ibbe_del7::{IBBEDel7, UserIdentity};
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::time::Instant;
use crate::hybrid_encryption::HybridEncryption;

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

    pub fn test_extract<T: Into<Vec<u8>> + Clone + PartialEq>(number_of_iterations: u128) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let number_of_users = 10u32;

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = rng.gen_range(0..number_of_users);

            let start_time: Instant = Instant::now();
            _ = ibbe.extract(&UserIdentity {
                identity: String::from(user_id.to_string()),
            });
            let end_time: Instant = Instant::now();

            total_execution_time += end_time.duration_since(start_time).as_nanos()
        }

        let avg_duration = total_execution_time / number_of_iterations;
        println!(
            "test_extract: {} ms on average",
            avg_duration as f64 / 1000000.0
        );
    }

    pub fn test_encrypt<T: Into<Vec<u8>> + Clone + PartialEq>(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let users_id: Vec<u32> = (0..number_of_users).collect();
        let mut set_of_users = Vec::new();
        for id in users_id {
            set_of_users.push(UserIdentity {
                identity: String::from(rng.gen_range(0..number_of_users).to_string()),
            });
        }

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = UserIdentity {
                identity: String::from(rng.gen_range(0..number_of_users).to_string()),
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

    pub fn test_decrypt<T: Into<Vec<u8>> + Clone + PartialEq>(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time = 0u128;
        let mut rng = rand::thread_rng();
        let mut set_of_users = tools::crete_set_of_identities(number_of_users);

        let ibbe = IBBEDel7::setup(number_of_users);

        for _ in 0..number_of_iterations {
            let user_id = UserIdentity {
                identity: String::from(rng.gen_range(0..number_of_users).to_string()),
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

    pub fn test_complex<T: Into<Vec<u8>> + Clone + PartialEq>(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time_setup = 0u128;
        let mut total_execution_time_extract = 0u128;
        let mut total_execution_time_encrypt = 0u128;
        let mut total_execution_time_decrypt = 0u128;

        let mut rng = rand::thread_rng();
        let set_of_users = tools::crete_set_of_identities(number_of_users);

        for _ in 0..number_of_iterations {
            let start_time: Instant = Instant::now();
            let ibbe = IBBEDel7::setup(number_of_users);
            let end_time: Instant = Instant::now();
            total_execution_time_setup += end_time.duration_since(start_time).as_nanos();

            let user_id = UserIdentity {
                identity: String::from(rng.gen_range(0..number_of_users).to_string()),
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

    pub fn test_signature_complex<T: Into<Vec<u8>> + Clone + PartialEq>(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time_signature = 0u128;
        let mut total_execution_time_verification = 0u128;

        let mut rng = rand::thread_rng();
        let set_of_users = tools::crete_set_of_identities(number_of_users);

        for _ in 0..number_of_iterations {
            let ibbe = IBBEDel7::setup(number_of_users);

            let user_id = UserIdentity {
                identity: String::from(rng.gen_range(0..number_of_users).to_string()),
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

    pub fn test_art<T: Into<Vec<u8>> + Clone + PartialEq>(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time = HashMap::new();
        total_execution_time.insert("compute_art_by_trusted_party", 0);
        total_execution_time.insert("serialisation", 0);
        total_execution_time.insert("deserialization", 0);
        total_execution_time.insert("compute_root_key", 0);
        total_execution_time.insert("update_key", 0);
        total_execution_time.insert("update_branch", 0);

        let mut rng = rand::thread_rng();

        for _ in 0..number_of_iterations {
            let ibbe = IBBEDel7::setup(number_of_users);
            let mut users = tools::crete_set_of_identities(number_of_users);

            let user_index = rand::thread_rng().gen_range(0..number_of_users) as usize;
            let user = users[user_index].clone();
            let sk_id = ibbe.extract(&user).unwrap();

            let msk = ibbe.msk.clone().expect("Secret key must be set up.");
            let mut art_agent = ARTAgent::new(msk, ibbe.pk.clone());

            let start_time: Instant = Instant::now();
            let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("compute_art_by_trusted_party")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            let serialized = serde_json::to_string(&tree).unwrap();
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("serialisation")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            let deserialized: ART = serde_json::from_str(&serialized).unwrap();
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("deserialization")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            let computed_key2 =
                tree.compute_root_key(ciphertexts[user_index], sk_id, &ibbe.pk.get_h());
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("compute_root_key")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            let (new_key, changes) = tree.update_key().unwrap();
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_key")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = tree.update_branch(&changes);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_branch")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());
        }

        println!();
        for (key, val) in total_execution_time {
            println!(
                "test {key} {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
                (val as f64 / number_of_iterations as f64) / 1000000.0
            );
        }
    }

    pub fn test_hibbe(
        number_of_users: u32,
        number_of_iterations: u128,
    ) {
        let mut total_execution_time = HashMap::new();
        total_execution_time.insert("encrypt", 0);
        total_execution_time.insert("decrypt", 0);
        total_execution_time.insert("update_stage_key", 0);

        let mut rng = rand::thread_rng();

        for _ in 0..number_of_iterations {
            let number_of_users = 15u32;
            let users = tools::crete_set_of_identities(number_of_users);

            let index1 = thread_rng().gen_range(0..number_of_users as usize);
            let mut index2 = index1;
            while index2 == index1 {
                index2 = thread_rng().gen_range(0..number_of_users as usize);
            }

            let user1 = users.get(index1).unwrap().clone();
            let user2 = users.get(index2).unwrap().clone();

            let ibbe = IBBEDel7::setup(number_of_users);
            let sk_id1 = ibbe.extract(&user1).unwrap();
            let sk_id2 = ibbe.extract(&user2).unwrap();

            let mut art_agent = ARTAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
            let (_, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&users);

            let mut tree1 = art_agent.get_recomputed_art();
            tree1.remove_root_key();
            tree1.compute_root_key(ciphertexts[index1], sk_id1, &ibbe.pk.get_h());

            let mut tree2 = art_agent.get_recomputed_art();
            tree2.remove_root_key();
            tree2.compute_root_key(ciphertexts[index2], sk_id2, &ibbe.pk.get_h());

            let mut hibbe1 =
                HybridEncryption::new(ibbe.clone(), tree1, users.clone(), user1.clone(), sk_id1);
            let mut hibbe2 =
                HybridEncryption::new(ibbe.clone(), tree2, users.clone(), user2.clone(), sk_id2);

            let message = String::from(
                "111111111122222222223333333333444444444455555555556666666666",
            );

            let start_time: Instant = Instant::now();
            let (ciphertext, changes) = hibbe1.encrypt(message);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("encrypt")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());


            let start_time: Instant = Instant::now();
            let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("decrypt")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            hibbe1.update_stage_key();
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_stage_key")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());
        }

        println!();
        for (key, val) in total_execution_time {
            println!(
                "test {key}, {number_of_iterations} iterations: {} ms on average",
                (val as f64 / number_of_iterations as f64) / 1000000.0
            );
        }
    }
}
