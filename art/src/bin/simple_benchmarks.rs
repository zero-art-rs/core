use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use ark_std::UniformRand;
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use bulletproofs::PedersenGens;
use chrono::Local;
use cortado::{ALT_GENERATOR_X, ALT_GENERATOR_Y, CortadoAffine, Fr};
use curve25519_dalek::Scalar;
use std::collections::HashMap;
use std::fmt;
use std::ops::{AddAssign, Mul};
use std::time::{Duration, Instant};
use tracing::info;
use tracing_subscriber::fmt::{format::Writer, time::FormatTime};
use zkp::rand::thread_rng;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;
use zrt_art::art::PrivateART;
use zrt_zk::art::{art_prove, art_verify};
use zrt_zk::cred::Credential;

const TEST_SAMPLES: [usize; 6] = [4, 10, 14, 16, 18, 20];
const REPETITION_TIME: usize = 50;

struct LocalTimer;

impl FormatTime for LocalTimer {
    fn format_time(&self, w: &mut Writer<'_>) -> fmt::Result {
        let now = Local::now();
        write!(w, "[{}]", now.format("%Y-%m-%d %H:%M:%S"))
    }
}

/// Try to init console logger with RUST_LOG level filter
pub fn init_tracing_for_test() {
    _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_timer(LocalTimer)
        .with_target(false)
        .try_init();
}

fn update_table<'a>(
    table: &mut HashMap<&'a str, Vec<Duration>>,
    test_name: &'a str,
    group_size_index: usize,
    finish: Duration,
) {
    table.entry(test_name).or_insert_with(|| {
        (0..TEST_SAMPLES.len())
            .map(|_| Duration::ZERO)
            .collect::<Vec<_>>()
    })[group_size_index]
        .add_assign(finish);
}

fn public_of(secrets: &[Fr]) -> Vec<CortadoAffine> {
    secrets
        .iter()
        .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
        .collect()
}

fn bench_separate_operations_creation() {
    info!("Bench separate operations creation");

    const UPDATE_KEY: &str = "Update key";
    const PROVE_UPDATE_KEY: &str = "Prove update key";
    const VERIFY_UPDATE_KEY: &str = "Verify update key";
    const APPLY_UPDATE_KEY: &str = "Apply update key";

    const ADD_MEMBER: &str = "Add member";
    const PROVE_ADD_MEMBER: &str = "Prove add member";
    const VERIFY_ADD_MEMBER: &str = "Verify add member";
    const APPLY_ADD_MEMBER: &str = "Apply add member";

    const MAKE_BLANK: &str = "Make blank";
    const PROVE_MAKE_BLANK: &str = "Prove make blank";
    const VERIFY_MAKE_BLANK: &str = "Verify make blank";
    const APPLY_MAKE_BLANK: &str = "Apply make blank";

    // table: type x group size
    let mut time_table = HashMap::<&str, Vec<Duration>>::new();

    // Create pedersen basis
    let g_1 = CortadoAffine::generator();
    let h_1 = CortadoAffine::new_unchecked(ALT_GENERATOR_X, ALT_GENERATOR_Y);
    let gens = PedersenGens::default();
    let pedersen_basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
        g_1,
        h_1,
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    );

    // init test
    for (i, group_size) in TEST_SAMPLES.iter().enumerate() {
        info!(
            "Testing group of size: 2^{} ({}) ...",
            group_size,
            2usize.pow(*group_size as u32)
        );

        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        ///////////////////////////////////////////////////////////
        // PrivateART creation
        ///////////////////////////////////////////////////////////

        let secrets = (0..2usize.pow(*group_size as u32))
            .map(|_| Fr::rand(&mut rng))
            .collect();

        let start = Instant::now();
        let def_private_art =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
                .unwrap()
                .0;
        info!("\t> Spend {:?} on art creation.", start.elapsed());

        let start = Instant::now();
        // update_table(&mut time_table, CREATION, i, start.elapsed());
        let def_other_private_art = PrivateART::from_public_art_and_secret(
            def_private_art.get_public_art().clone(),
            secrets[1],
        )
        .unwrap();
        info!("\t> Spend {:?} on art clone.", start.elapsed());

        let group_test_start = Instant::now();
        for _ in 0..REPETITION_TIME {
            let mut private_art = def_private_art.clone();
            let mut other_private_art = def_other_private_art.clone();

            {
                ///////////////////////////////////////////////////////////
                // Update key
                ///////////////////////////////////////////////////////////

                let sk = Fr::rand(&mut rng);

                let start = Instant::now();
                let (update_key_tk, update_key_change, update_key_artefacts) =
                    private_art.update_key(&sk).unwrap();
                update_table(&mut time_table, UPDATE_KEY, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Prove update key
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![update_key_tk.key];
                let public_aux_keys = aux_keys
                    .iter()
                    .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
                    .collect::<Vec<_>>();
                let associated_data = b"associated data".to_vec();

                let start = Instant::now();
                let proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &update_key_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();
                update_table(&mut time_table, PROVE_UPDATE_KEY, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Verify update key
                ///////////////////////////////////////////////////////////

                // Prepare verifier_artefacts
                let verifier_artefacts = private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&update_key_change)
                    .unwrap();

                let start = Instant::now();
                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    proof,
                )
                .unwrap();
                update_table(&mut time_table, VERIFY_UPDATE_KEY, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Apply update key
                ///////////////////////////////////////////////////////////

                let start = Instant::now();
                other_private_art.update(&update_key_change).unwrap();
                update_table(&mut time_table, APPLY_UPDATE_KEY, i, start.elapsed());
            }

            {
                ///////////////////////////////////////////////////////////
                // Add member
                ///////////////////////////////////////////////////////////

                let sk = Fr::rand(&mut rng);
                let start = Instant::now();
                let (add_member_tk, add_member_change, add_member_artefacts) =
                    private_art.append_or_replace_node(&sk).unwrap();
                update_table(&mut time_table, ADD_MEMBER, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Prove add member
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![add_member_tk.key];
                let public_aux_keys = public_of(&aux_keys);
                let associated_data = b"associated data".to_vec();

                let start = Instant::now();
                let add_member_proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &add_member_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();
                update_table(&mut time_table, PROVE_ADD_MEMBER, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Verify add member
                ///////////////////////////////////////////////////////////

                // Prepare verifier_artefacts
                let verifier_artefacts = other_private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&add_member_change)
                    .unwrap();

                let start = Instant::now();
                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    add_member_proof,
                )
                .unwrap();
                update_table(&mut time_table, VERIFY_ADD_MEMBER, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Apply add member
                ///////////////////////////////////////////////////////////

                let start = Instant::now();
                other_private_art.update(&add_member_change).unwrap();
                update_table(&mut time_table, APPLY_ADD_MEMBER, i, start.elapsed());
            }

            {
                ///////////////////////////////////////////////////////////
                // Make blank
                ///////////////////////////////////////////////////////////

                let sk = Fr::rand(&mut rng);
                let target_node = private_art
                    .get_public_art()
                    .get_path_to_leaf(&private_art.public_key_of(&secrets[2]))
                    .unwrap();

                let start = Instant::now();
                let (make_blank_tk, make_blank_change, make_blank_artefacts) =
                    private_art.make_blank(&target_node, &sk).unwrap();
                update_table(&mut time_table, MAKE_BLANK, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Prove make blank
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![make_blank_tk.key];
                let public_aux_keys = aux_keys
                    .iter()
                    .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
                    .collect::<Vec<_>>();
                let associated_data = b"associated data".to_vec();

                let start = Instant::now();
                let proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &make_blank_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();
                update_table(&mut time_table, PROVE_MAKE_BLANK, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Verify make blank
                ///////////////////////////////////////////////////////////

                // Prepare verifier_artefacts
                let verifier_artefacts = private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&make_blank_change)
                    .unwrap();

                let start = Instant::now();
                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    proof,
                )
                .unwrap();
                update_table(&mut time_table, VERIFY_MAKE_BLANK, i, start.elapsed());

                ///////////////////////////////////////////////////////////
                // Apply make blank
                ///////////////////////////////////////////////////////////

                let start = Instant::now();
                other_private_art.update(&make_blank_change).unwrap();
                update_table(&mut time_table, APPLY_MAKE_BLANK, i, start.elapsed());
            }
        }

        info!(
            "\t> Spent: {:?} on benchmarking for group of size 2^{} ({}).",
            group_test_start.elapsed(),
            group_size,
            2usize.pow(*group_size as u32)
        );

        for (_, test_type) in time_table.iter_mut() {
            test_type[i] /= REPETITION_TIME as u32;
        }
    }

    info!("Operations time for tests: {:#?}", time_table);
}

fn bench_operations_in_combination() {
    info!("Benchmarking operations in combination");

    const UPDATE_KEY: &str = "Update key";
    const ADD_MEMBER: &str = "Add member";
    const MAKE_BLANK: &str = "Make blank";

    const APPLY_UPDATE_KEY: &str = "Apply update key";
    const APPLY_ADD_MEMBER: &str = "Apply add member";
    const APPLY_MAKE_BLANK: &str = "Apply make blank";

    // table: type x group size
    let mut time_table = HashMap::<&str, Vec<Duration>>::new();

    // Create pedersen basis
    let g_1 = CortadoAffine::generator();
    let h_1 = CortadoAffine::new_unchecked(ALT_GENERATOR_X, ALT_GENERATOR_Y);
    let gens = PedersenGens::default();
    let pedersen_basis = PedersenBasis::<CortadoAffine, Ed25519Affine>::new(
        g_1,
        h_1,
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    );

    // init test
    for (i, group_size) in TEST_SAMPLES.iter().enumerate() {
        info!(
            "Testing group of size: 2^{} ({}) ...",
            group_size,
            2usize.pow(*group_size as u32)
        );

        let mut rng = &mut StdRng::seed_from_u64(rand::random());

        ///////////////////////////////////////////////////////////
        // PrivateART creation
        ///////////////////////////////////////////////////////////

        let secrets = (0..2usize.pow(*group_size as u32))
            .map(|_| Fr::rand(&mut rng))
            .collect();

        let start = Instant::now();
        let def_private_art =
            PrivateART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
                .unwrap()
                .0;
        info!("\t> Spend {:?} on art creation.", start.elapsed());

        let start = Instant::now();
        // update_table(&mut time_table, CREATION, i, start.elapsed());
        let def_other_private_art = PrivateART::from_public_art_and_secret(
            def_private_art.get_public_art().clone(),
            secrets[1],
        )
        .unwrap();
        info!("\t> Spend {:?} on art clone.", start.elapsed());

        let group_test_start = Instant::now();
        for _ in 0..REPETITION_TIME {
            let mut private_art = def_private_art.clone();
            let mut other_private_art = def_other_private_art.clone();

            {
                ///////////////////////////////////////////////////////////
                // Update key
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                let sk = Fr::rand(&mut rng);
                let (update_key_tk, update_key_change, update_key_artefacts) =
                    private_art.update_key(&sk).unwrap();

                ///////////////////////////////////////////////////////////
                // Prove update key
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![update_key_tk.key];
                let public_aux_keys = aux_keys
                    .iter()
                    .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
                    .collect::<Vec<_>>();
                let associated_data = b"associated data".to_vec();

                let proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &update_key_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();

                update_table(&mut time_table, UPDATE_KEY, i, start.elapsed());
                ///////////////////////////////////////////////////////////
                // Verify update key
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                // Prepare verifier_artefacts
                let verifier_artefacts = private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&update_key_change)
                    .unwrap();

                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    proof,
                )
                .unwrap();

                ///////////////////////////////////////////////////////////
                // Apply update key
                ///////////////////////////////////////////////////////////

                other_private_art.update(&update_key_change).unwrap();

                update_table(&mut time_table, APPLY_UPDATE_KEY, i, start.elapsed());
            }

            {
                ///////////////////////////////////////////////////////////
                // Add member
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                let sk = Fr::rand(&mut rng);
                let (add_member_tk, add_member_change, add_member_artefacts) =
                    private_art.append_or_replace_node(&sk).unwrap();

                ///////////////////////////////////////////////////////////
                // Prove add member
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![add_member_tk.key];
                let public_aux_keys = public_of(&aux_keys);
                let associated_data = b"associated data".to_vec();

                let add_member_proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &add_member_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();

                update_table(&mut time_table, ADD_MEMBER, i, start.elapsed());
                ///////////////////////////////////////////////////////////
                // Verify add member
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                // Prepare verifier_artefacts
                let verifier_artefacts = other_private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&add_member_change)
                    .unwrap();

                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    add_member_proof,
                )
                .unwrap();

                ///////////////////////////////////////////////////////////
                // Apply add member
                ///////////////////////////////////////////////////////////

                other_private_art.update(&add_member_change).unwrap();

                update_table(&mut time_table, APPLY_ADD_MEMBER, i, start.elapsed());
            }

            {
                ///////////////////////////////////////////////////////////
                // Make blank
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                let sk = Fr::rand(&mut rng);
                let target_node = private_art
                    .get_public_art()
                    .get_path_to_leaf(&private_art.public_key_of(&secrets[2]))
                    .unwrap();

                let (make_blank_tk, make_blank_change, make_blank_artefacts) =
                    private_art.make_blank(&target_node, &sk).unwrap();

                ///////////////////////////////////////////////////////////
                // Prove make blank
                ///////////////////////////////////////////////////////////

                // Prepare aux keys, blinding vector, associated date
                let aux_keys = vec![make_blank_tk.key];
                let public_aux_keys = aux_keys
                    .iter()
                    .map(|sk| CortadoAffine::generator().mul(sk).into_affine())
                    .collect::<Vec<_>>();
                let associated_data = b"associated data".to_vec();

                let proof = art_prove(
                    pedersen_basis.clone(),
                    &associated_data,
                    &make_blank_artefacts
                        .to_prover_branch(&mut thread_rng())
                        .unwrap(),
                    public_aux_keys.clone(),
                    aux_keys.clone(),
                )
                .unwrap();

                update_table(&mut time_table, MAKE_BLANK, i, start.elapsed());
                ///////////////////////////////////////////////////////////
                // Verify make blank
                ///////////////////////////////////////////////////////////
                let start = Instant::now();

                // Prepare verifier_artefacts
                let verifier_artefacts = private_art
                    .get_public_art()
                    .compute_artefacts_for_verification(&make_blank_change)
                    .unwrap();

                art_verify(
                    pedersen_basis.clone(),
                    &associated_data,
                    &verifier_artefacts.to_verifier_branch().unwrap(),
                    public_aux_keys.clone(),
                    proof,
                )
                .unwrap();

                ///////////////////////////////////////////////////////////
                // Apply make blank
                ///////////////////////////////////////////////////////////

                other_private_art.update(&make_blank_change).unwrap();

                update_table(&mut time_table, APPLY_MAKE_BLANK, i, start.elapsed());
            }
        }

        info!(
            "\t> Spent: {:?} on benchmarking for group of size 2^{} ({}).",
            group_test_start.elapsed(),
            group_size,
            2usize.pow(*group_size as u32)
        );

        for (_, test_type) in time_table.iter_mut() {
            test_type[i] /= REPETITION_TIME as u32;
        }
    }

    info!("Operations time for tests: {:#?}", time_table);
}

fn bench_credentials() {
    info!("Benchmarking credentials");
    const ISSUE_CREDENTIAL: &str = "Issue a credential";
    const VERIFY_CREDENTIAL: &str = "Verify the credential";
    const CREATE_PRESENTATION_PROOF: &str = "Create a credential presentation proof";
    const VERIFY_PRESENTATION_PROOF: &str = "Verify the credential presentation proof";

    // table: type x group size
    let mut time_table = HashMap::<&str, Vec<Duration>>::new();

    let validity_period = 3600; // 1 hour validity
    let revocation_list = vec![
        Scalar::from(1u64),
        Scalar::from(2u64),
        Scalar::from(3u64),
        Scalar::from(4u64),
    ]; // Example revocation list

    let group_test_start = Instant::now();
    for _ in 0..REPETITION_TIME {
        let holder_secret_key = Fr::rand(&mut ark_std::rand::thread_rng());
        let holder_public_key = (CortadoAffine::generator() * holder_secret_key).into_affine();
        let issuer_secret_key = Fr::rand(&mut ark_std::rand::thread_rng());

        // Issue a credential
        let start = Instant::now();
        let credential =
            Credential::issue(issuer_secret_key, validity_period, holder_public_key).unwrap();
        update_table(&mut time_table, ISSUE_CREDENTIAL, 0, start.elapsed());

        // Verify the credential
        let start = Instant::now();
        assert!(credential.verify().is_ok());
        update_table(&mut time_table, VERIFY_CREDENTIAL, 0, start.elapsed());

        // Create a credential presentation proof
        let start = Instant::now();
        let proof = credential
            .present(holder_secret_key, revocation_list.clone())
            .unwrap();
        update_table(
            &mut time_table,
            CREATE_PRESENTATION_PROOF,
            0,
            start.elapsed(),
        );

        // Verify the credential presentation proof
        let start = Instant::now();
        assert!(Credential::verify_presentation(&proof, revocation_list.clone()).is_ok());
        update_table(
            &mut time_table,
            VERIFY_PRESENTATION_PROOF,
            0,
            start.elapsed(),
        );
    }

    info!(
        "\t> Spent: {:?} on benchmarking.",
        group_test_start.elapsed(),
    );

    for (_, test_type) in time_table.iter_mut() {
        test_type[0] /= REPETITION_TIME as u32;
    }

    info!("Operations time for tests: {:#?}", time_table);
}

fn main() {
    init_tracing_for_test();
    bench_separate_operations_creation();
    bench_operations_in_combination();
    bench_credentials();
}
