use super::*;
use crate::art::{ART, ARTTrustedAgent, ARTUserAgent};
use crate::hybrid_encryption::HybridEncryption;
use crate::ibbe_del7::{IBBEDel7, UserIdentity};
use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use rand::{Rng, thread_rng};
use std::collections::HashMap;
use std::ops::Mul;
use std::time::Instant;

pub struct SpeedMetrics {}

impl SpeedMetrics {
    pub fn test_ibbe(number_of_users: u32, number_of_iterations: u128) {
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
            "test_ibbe_setup {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_setup as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_ibbe_extract {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_extract as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_ibbe_encrypt {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_encrypt as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_ibbe_decrypt {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_decrypt as f64 / number_of_iterations as f64) / 1000000.0
        );
    }

    pub fn test_signature_complex(number_of_users: u32, number_of_iterations: u128) {
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
            "test_ibbe_based_signature {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_signature as f64 / number_of_iterations as f64) / 1000000.0
        );
        println!(
            "test_ibbe_based_signature_verification {number_of_iterations} iterations: {} ms on average",
            (total_execution_time_verification as f64 / number_of_iterations as f64) / 1000000.0
        );
    }

    pub fn test_art(number_of_users: u32, number_of_iterations: u128) {
        let mut total_execution_time = HashMap::new();
        total_execution_time.insert("compute_art_by_trusted_party", 0);
        total_execution_time.insert("serialisation", 0);
        total_execution_time.insert("deserialization", 0);
        total_execution_time.insert("create_user_agent", 0);
        total_execution_time.insert("update_key", 0);
        total_execution_time.insert("update_branch_key_rotation", 0);
        total_execution_time.insert("update_branch_append_node", 0);
        total_execution_time.insert("update_branch_remove_node", 0);
        total_execution_time.insert("update_branch_make_temporal", 0);
        total_execution_time.insert("append_node", 0);
        total_execution_time.insert("remove_node", 0);
        total_execution_time.insert("make_temporal", 0);

        let mut rng = rand::thread_rng();

        for _ in 0..number_of_iterations {
            let ibbe = IBBEDel7::setup(number_of_users);
            let mut users = tools::crete_set_of_identities(number_of_users);

            let index_for_removal = 2;
            let mut index1 = 0; // can remove nodes 1, 2 and 3
            let mut index2 = index_for_removal;
            while index2 == index_for_removal || index2 == index1 {
                index2 = thread_rng().gen_range(0..number_of_users as usize);
            }

            let user_for_removal = users.get(index_for_removal).unwrap().clone();
            let user1 = users.get(index1).unwrap().clone();
            let user2 = users.get(index2).unwrap().clone();

            let sk_idr = ibbe.extract(&user_for_removal).unwrap();
            let sk_id1 = ibbe.extract(&user1).unwrap();
            let sk_id2 = ibbe.extract(&user2).unwrap();

            let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
            let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

            let tree_json = tree.serialise().unwrap();

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

            let tree_json = tree.serialise().unwrap();
            let start_time: Instant = Instant::now();
            let mut user_agent = ARTUserAgent::new(tree_json, ciphertexts[index1], sk_id1);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("createe user agent")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            let (new_key, changes) = user_agent.update_key().unwrap();
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_key")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let mut user2_agent =
                ARTUserAgent::new(tree.serialise().unwrap(), ciphertexts[index2], sk_id2);

            let start_time: Instant = Instant::now();
            _ = user2_agent.update_branch(&changes);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_branch_key_rotation")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let lambda = Bn254::pairing(ciphertexts[index_for_removal].c, sk_idr.sk).0;
            let secret_key = ART::convert_lambda_to_scalar_field(&lambda);
            let public_key = ibbe.pk.get_h().mul(secret_key);

            let start_time: Instant = Instant::now();
            _ = user_agent.remove_node(public_key);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("remove_node")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = user2_agent.update_branch(&changes);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_branch_remove_node")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = user_agent.append_node(lambda);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("append_node")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = user2_agent.update_branch(&changes);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_branch_append_node")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = user_agent.make_temporal(public_key);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("make_temporal")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());

            let start_time: Instant = Instant::now();
            _ = user2_agent.update_branch(&changes);
            let end_time: Instant = Instant::now();
            total_execution_time
                .entry("update_branch_make_temporal")
                .and_modify(|k| *k += end_time.duration_since(start_time).as_nanos());
        }

        println!();
        for (key, val) in total_execution_time {
            println!(
                "test ART {key} {number_of_users} users, {number_of_iterations} iterations: {} ms on average",
                (val as f64 / number_of_iterations as f64) / 1000000.0
            );
        }
    }

    pub fn test_hibbe(number_of_users: u32, number_of_iterations: u128) {
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

            let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
            let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&users);

            let tree_json = tree.serialise().unwrap();
            let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
            let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index2], sk_id2);

            let mut hibbe1 = HybridEncryption::new(
                ibbe.clone(),
                user1_agent,
                users.clone(),
                user1.clone(),
                sk_id1,
            );
            let mut hibbe2 = HybridEncryption::new(
                ibbe.clone(),
                user2_agent,
                users.clone(),
                user2.clone(),
                sk_id2,
            );

            let message =
                String::from("111111111122222222223333333333444444444455555555556666666666");

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
                "test hibbe {key}, {number_of_iterations} iterations: {} ms on average",
                (val as f64 / number_of_iterations as f64) / 1000000.0
            );
        }
    }
}
