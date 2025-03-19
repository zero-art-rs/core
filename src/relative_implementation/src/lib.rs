pub mod art;
pub mod hybrid_encryption;
pub mod ibbe_del7;
pub mod schnorr;
pub mod time_measurements;
pub mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::art::ARTUserAgent;
    use crate::{
        art::ARTTrustedAgent, hybrid_encryption::HybridEncryption, ibbe_del7::IBBEDel7, tools,
    };
    use ark_ec::pairing::Pairing;
    use rand::{Rng, thread_rng};
    use std::ops::{Add, Mul};

    #[test]
    fn test_ibbedel7_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let users = tools::crete_set_of_identities(number_of_users);
        let alice_id = thread_rng().gen_range(0..number_of_users as usize);
        let alice = users.get(alice_id).unwrap();
        let sk_id = ibbe.extract(&alice).unwrap();

        let (hdr, key) = ibbe.encrypt(&users);

        let decrypted_key = ibbe.decrypt(&users, &alice, &sk_id, &hdr);

        // correct encryption
        assert_eq!(key.key, decrypted_key.key);

        let message = String::from("Some string");
        let sigma = ibbe.sign(&message, &sk_id);

        // correct signature
        assert!(ibbe.verify(&message, &sigma, &alice));
    }

    #[test]
    fn test_art_tree_key_computation_with_random_values() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let mut users = tools::crete_set_of_identities(number_of_users);

        let alice_id = thread_rng().gen_range(0..number_of_users as usize);
        let user = users[alice_id].clone();
        let sk_id = ibbe.extract(&user).unwrap();

        let msk = ibbe.msk.clone().expect("Secret key must be set up.");
        let mut art_agent = ARTTrustedAgent::new(msk, ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();
        let mut user_agent = ARTUserAgent::new(tree_json, ciphertexts[alice_id], sk_id);

        let computed_root_key = user_agent.root_key;

        assert_eq!(computed_root_key.key, root_key.key);
    }

    #[test]
    fn test_art_tree_update() {
        let number_of_users = 15u32;
        let ibbe = IBBEDel7::setup(number_of_users);

        let mut users = tools::crete_set_of_identities(number_of_users);

        let user_id = thread_rng().gen_range(0..number_of_users as usize);
        let user = users[user_id].clone();
        let sk_id = ibbe.extract(&user).unwrap();

        let msk = ibbe.msk.clone().expect("Secret key must be set up.");
        let mut art_agent = ARTTrustedAgent::new(msk, ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();
        let mut user_agent = ARTUserAgent::new(tree_json, ciphertexts[user_id], sk_id);

        let computed_root_key = user_agent.root_key;

        // Assert trusted party and users computed the same tree key. Skip lambda because trusted party cant compute it
        assert_eq!(computed_root_key.key, root_key.key);

        let (new_key, _) = user_agent.update_key().unwrap();

        // Assert tree.update_key() changes key and lambda
        assert_ne!(computed_root_key.key, new_key.key);
        assert_ne!(computed_root_key.lambda, new_key.lambda);

        let (old_updated_key, _) = user_agent
            .change_lambda(computed_root_key.lambda.unwrap())
            .unwrap();

        // Assert, that change of lambdas: lambda1 -> lambda2 -> lambda1, gives the same values
        assert_eq!(computed_root_key.lambda, old_updated_key.lambda);
        assert_eq!(computed_root_key.key, old_updated_key.key);
    }

    #[test]
    fn test_art_update_from_two_users() {
        let number_of_users = 20u32;
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
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let computed_root_key = user1_agent.root_key;

        let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index2], sk_id2);
        let computed_root_key = user2_agent.root_key;

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);
    }

    #[test]
    fn test_art_update_branch() {
        let number_of_users = 20;
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
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let computed_root_key = user1_agent.root_key;

        let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index2], sk_id2);
        let computed_root_key = user2_agent.root_key;

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        let (key, changes) = user1_agent.update_key().unwrap();

        assert_ne!(user1_agent.root_key.key, user2_agent.root_key.key);

        _ = user2_agent.update_branch(&changes);

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);
    }

    #[test]
    fn test_art_append_node() {
        let number_of_users = 20;
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
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index2], sk_id2);

        let lambda = user1_agent.lambda.add(user1_agent.lambda);
        let (root_key, changes) = user1_agent.append_node(lambda).unwrap();

        _ = user2_agent.update_branch(&changes);

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        let (key, changes) = user1_agent.update_key().unwrap();
    }

    #[test]
    fn test_art_make_temporal() {
        let number_of_users = 20;
        let users = tools::crete_set_of_identities(number_of_users);

        let index1 = thread_rng().gen_range(0..number_of_users as usize);
        let mut index2 = index1;
        while index2 == index1 {
            index2 = thread_rng().gen_range(0..number_of_users as usize);
        }
        let mut index3 = index1;
        while index3 == index1 || index3 == index2 {
            index3 = thread_rng().gen_range(0..number_of_users as usize);
        }

        let user1 = users.get(index1).unwrap().clone();
        let user2 = users.get(index2).unwrap().clone();
        let user3 = users.get(index3).unwrap().clone();

        let ibbe = IBBEDel7::setup(number_of_users);
        let sk_id1 = ibbe.extract(&user1).unwrap();
        let sk_id2 = ibbe.extract(&user2).unwrap();
        let sk_id3 = ibbe.extract(&user3).unwrap();

        let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let mut user2_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index2], sk_id2);
        let mut user3_agent = ARTUserAgent::new(tree_json, ciphertexts[index3], sk_id3);

        let (root_key, changes) = user1_agent.make_temporal(user3_agent.public_key()).unwrap();

        assert_ne!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        _ = user2_agent.update_branch(&changes);

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);
    }

    #[test]
    fn test_art_remove_node() {
        let number_of_users = 20;
        let users = tools::crete_set_of_identities(number_of_users);

        let index1 = 2; // working for 1, and should work for 2 and 3
        let mut index2 = 0;
        let mut index3 = index1;
        while index3 == index1 || index3 == index2 {
            index3 = thread_rng().gen_range(0..number_of_users as usize);
        }

        let user1 = users.get(index1).unwrap().clone();
        let user2 = users.get(index2).unwrap().clone();
        let user3 = users.get(index3).unwrap().clone();

        let ibbe = IBBEDel7::setup(number_of_users);
        let sk_id1 = ibbe.extract(&user1).unwrap();
        let sk_id2 = ibbe.extract(&user2).unwrap();
        let sk_id3 = ibbe.extract(&user3).unwrap();

        let mut art_agent = ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        // Numeration is shifted for convenience, because user3_agent and user1_agent are
        // neighbours, so they can remove the node appropriately
        let mut user3_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index2], sk_id2);
        let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index3], sk_id3);

        assert!(user1_agent.can_remove(user3_agent.public_key()));
        let (root_key, changes) = user1_agent.remove_node(user3_agent.public_key()).unwrap();

        assert_ne!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        _ = user2_agent.update_branch(&changes);

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        let (root_key, changes) = user1_agent.append_node(user3_agent.lambda).unwrap();

        assert_ne!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);

        _ = user2_agent.update_branch(&changes);

        assert_eq!(user1_agent.root_key.key, user2_agent.root_key.key);
        assert_ne!(user1_agent.root_key.lambda, user2_agent.root_key.lambda);
    }

    #[test]
    fn test_hibbe_encryption() {
        let number_of_users = 20u32;
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
        let (mut tree, ciphertexts, root_key) = art_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut user1_agent = ARTUserAgent::new(tree_json.clone(), ciphertexts[index1], sk_id1);
        let computed_root_key = user1_agent.root_key;

        let mut user2_agent = ARTUserAgent::new(tree_json, ciphertexts[index2], sk_id2);
        let computed_root_key = user2_agent.root_key;

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

        let message = String::from("ffffffffffffffffffffffffff7777777777777777777777777");
        let (ciphertext, changes) = hibbe1.encrypt(message.clone());
        let decrypted_message = hibbe2.decrypt(ciphertext.clone(), &changes.clone());
        // Assert the second user can decrypt the message
        assert_eq!(message, decrypted_message);

        let message2 = String::from("ccccccccccccccccccccccccccc7777777777777777777777777");
        let (ciphertext2, changes2) = hibbe2.encrypt(message2.clone());
        let decrypted_message2 = hibbe1.decrypt(ciphertext2.clone(), &changes2.clone());
        // Assert users can have a conversation
        assert_eq!(message2, decrypted_message2);
    }
}
