pub mod art;
pub mod hybrid_encryption;
pub mod ibbe_del7;
pub mod schnorr;
pub mod time_measurements;
pub mod tools;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::art::{ARTUserAgent, ART};
    use crate::{
        art::ARTTrustedAgent, hybrid_encryption::HybridEncryption, ibbe_del7::IBBEDel7, tools,
    };
    use ark_bn254::{
        Bn254, Fq12Config, G1Projective as G1, G2Projective as G2, fr::Fr as ScalarField,
    };
    use ark_ec::pairing::Pairing;
    use ark_ff::Fp12;
    use ark_std::UniformRand;
    use rand::{Rng, thread_rng};

    #[test]
    fn test_ibbedel7_with_random_values() {
        let number_of_users = 100;
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
    fn test_art_tree_key_update() {
        let number_of_users = 100;
        let ibbe = IBBEDel7::setup(number_of_users);

        let mut users = tools::crete_set_of_identities(number_of_users);

        let main_user_id = thread_rng().gen_range(0..number_of_users as usize);

        let mut trusted_agent = ARTTrustedAgent::from(&ibbe);
        let (mut tree, ciphertexts, trusted_root_key) =
            trusted_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut users_agents = Vec::new();
        for i in 0..number_of_users {
            let sk_id = ibbe.extract(users.get(i as usize).unwrap()).unwrap();
            users_agents.push(ARTUserAgent::new(
                ART::from_json(&tree_json.clone()).unwrap(),
                ciphertexts[i as usize],
                sk_id,
            ));
        }

        for user_agent in &users_agents {
            // Assert trusted party and users computed the same tree key. Skip lambda because trusted party cant compute it
            assert_eq!(user_agent.root_key.key, trusted_root_key.key);
        }

        let mut main_user_agent = users_agents.remove(main_user_id);

        // save old lambda to roll back
        let old_lambda = main_user_agent.lambda;
        let (new_key, changes) = main_user_agent.update_key().unwrap();

        for user_agent in &users_agents {
            assert_ne!(trusted_root_key.key, new_key.key);
            assert_ne!(trusted_root_key.lambda, new_key.lambda);
        }

        for user_agent in &mut users_agents {
            _ = user_agent.update_branch(&changes);
            assert_eq!(user_agent.root_key.key, new_key.key);
        }

        let (old_key, changes) = main_user_agent.change_lambda(old_lambda).unwrap();

        assert_eq!(trusted_root_key.key, old_key.key);

        for user_agent in &mut users_agents {
            _ = user_agent.update_branch(&changes);
            assert_eq!(user_agent.root_key.key, old_key.key);
        }
    }

    #[test]
    fn test_art_making_temporal() {
        let number_of_users = 100;
        let users = tools::crete_set_of_identities(number_of_users);

        let main_user_id = thread_rng().gen_range(0..(number_of_users - 2) as usize);
        let mut temporal_user_id = thread_rng().gen_range(0..(number_of_users - 3) as usize);
        while temporal_user_id >= main_user_id && temporal_user_id <= main_user_id + 2 {
            temporal_user_id = thread_rng().gen_range(0..(number_of_users - 3) as usize);
        }

        let ibbe = IBBEDel7::setup(number_of_users);

        let mut trusted_agent = ARTTrustedAgent::from(&ibbe);
        let (mut tree, ciphertexts, trusted_root_key) =
            trusted_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut users_agents = Vec::new();
        for i in 0..number_of_users {
            let sk_id = ibbe.extract(users.get(i as usize).unwrap()).unwrap();
            users_agents.push(ARTUserAgent::new(
                ART::from_json(&tree_json.clone()).unwrap(),
                ciphertexts[i as usize],
                sk_id,
            ));
        }

        for user_agent in &users_agents {
            // Assert trusted party and users computed the same tree key. Skip lambda because trusted party cant compute it
            assert_eq!(user_agent.root_key.key, trusted_root_key.key);
        }

        let mut main_user_agent = users_agents.remove(main_user_id);
        let mut temporal_user_agent = users_agents.remove(temporal_user_id);

        let (root_key, changes) = main_user_agent
            .make_temporal(temporal_user_agent.public_key())
            .unwrap();

        for user_agent in &mut users_agents {
            assert_ne!(user_agent.root_key.key, main_user_agent.root_key.key);
            assert_ne!(user_agent.root_key.lambda, main_user_agent.root_key.lambda);

            _ = user_agent.update_branch(&changes);

            assert_eq!(user_agent.root_key.key, main_user_agent.root_key.key);
            assert_ne!(user_agent.root_key.lambda, main_user_agent.root_key.lambda);
            assert_eq!(user_agent.tree.size(), (number_of_users - 1) as usize);
        }

        let mut rng = thread_rng();
        let new_lambda = Fp12::<Fq12Config>::rand(&mut rng);

        let (root_key, changes) = main_user_agent.append_node(new_lambda).unwrap();

        for user_agent in &mut users_agents {
            _ = user_agent.update_branch(&changes);

            assert_eq!(user_agent.root_key.key, main_user_agent.root_key.key);
            assert_ne!(user_agent.root_key.lambda, main_user_agent.root_key.lambda);
            assert_eq!(user_agent.tree.size(), number_of_users as usize);
        }
    }

    #[test]
    fn test_art_node_removal() {
        let number_of_users = 100;
        let users = tools::crete_set_of_identities(number_of_users);

        let temporal_user_id = thread_rng().gen_range(3..number_of_users as usize);

        let ibbe = IBBEDel7::setup(number_of_users);

        let mut trusted_agent = ARTTrustedAgent::from(&ibbe);
        let (mut tree, ciphertexts, trusted_root_key) =
            trusted_agent.compute_art_and_ciphertexts(&users);

        let tree_json = tree.serialise().unwrap();

        let mut users_agents = Vec::new();
        for i in 0..number_of_users {
            let sk_id = ibbe.extract(users.get(i as usize).unwrap()).unwrap();
            users_agents.push(ARTUserAgent::new(
                ART::from_json(&tree_json.clone()).unwrap(),
                ciphertexts[i as usize],
                sk_id,
            ));
        }

        for user_agent in &users_agents {
            // Assert trusted party and users computed the same tree key. Skip lambda because trusted party cant compute it
            assert_eq!(user_agent.root_key.key, trusted_root_key.key);
        }

        let mut main_user_agent = users_agents.remove(0);
        let mut main_user_neighbour = users_agents.remove(0);
        for i in 0..2 {
            let mut for_removal = users_agents.remove(0);

            let (root_key, changes) = main_user_agent
                .remove_node(for_removal.public_key())
                .unwrap();

            for user_agent in &mut users_agents {
                assert_ne!(user_agent.root_key.key, main_user_agent.root_key.key);

                _ = user_agent.update_branch(&changes);

                assert_eq!(user_agent.root_key.key, main_user_agent.root_key.key);
                assert_eq!(user_agent.tree.size(), (number_of_users - 1 - i) as usize);
            }
        }

        assert!(!main_user_agent.can_remove(users_agents[0].public_key()));

        let (root_key, changes) = main_user_agent
            .remove_node(main_user_neighbour.public_key())
            .unwrap();

        for user_agent in &mut users_agents {
            assert_ne!(user_agent.root_key.key, main_user_agent.root_key.key);

            _ = user_agent.update_branch(&changes);

            assert_eq!(user_agent.root_key.key, main_user_agent.root_key.key);
        }

        let (root_key, changes) = main_user_agent.append_node(main_user_neighbour.lambda).unwrap();

        for user_agent in &mut users_agents {
            _ = user_agent.update_branch(&changes);

            assert_eq!(user_agent.root_key.key, main_user_agent.root_key.key);
        }

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

        let mut user1_agent = ARTUserAgent::new(ART::from_json(&tree_json.clone()).unwrap(), ciphertexts[index1], sk_id1);

        let mut user2_agent = ARTUserAgent::new(ART::from_json(&tree_json).unwrap(), ciphertexts[index2], sk_id2);

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
