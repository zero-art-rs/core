use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::time::{Duration, Instant};

use ark_bn254::{
    fq::Fq, fq2::Fq2, fr::Fr as ScalarField, fr::FrConfig, Bn254, Fq12, Fq12Config,
    G1Projective as G1, G2Projective as G2,
};
use ark_ec::pairing::Pairing;
use ark_ff::{BigInt, Field, Fp, Fp12, Fp256, MontBackend, PrimeField};
use ark_std::UniformRand;
use hibbe::art::{ARTTrustedAgent, ARTUserAgent, ART};
use hibbe::ibbe_del7::{IBBEDel7, UserIdentity};
use hibbe::tools;
use rand::thread_rng;

// pub const TEST_SAMPLES: [u32; 5] = [100, 200, 300, 400, 500];
pub const TEST_SAMPLES: [u32; 3] = [100, 200, 300];

pub fn get_two_user_agents(group_size: u32) -> (ARTUserAgent, ARTUserAgent) {
    let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
    let samples = tools::get_subset_of_user_identities(2, &ibbe, &members).unwrap();

    let mut art_agent = ARTTrustedAgent::from(&ibbe);
    let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

    let mut user_agent1 = ARTUserAgent::new(tree, ciphertexts[samples[0].index], samples[0].sk_id);
    let mut user_agent2 = ARTUserAgent::new(
        art_agent.get_recomputed_art(),
        ciphertexts[samples[1].index],
        samples[1].sk_id,
    );

    (user_agent1, user_agent2)
}

pub fn get_several_user_agents(group_size: u32, number_of_agents: u32) -> Vec<ARTUserAgent> {
    let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
    let samples =
        tools::get_subset_of_user_identities(number_of_agents as usize, &ibbe, &members).unwrap();

    let mut art_agent = ARTTrustedAgent::from(&ibbe);
    let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

    let mut agents = Vec::new();
    for i in 0..number_of_agents as usize {
        agents.push(ARTUserAgent::new(
            art_agent.get_recomputed_art(),
            ciphertexts[samples[i].index],
            samples[i].sk_id,
        ))
    }

    agents
}

pub fn custom_iter_with_revert<F1, F2>(
    iters: u64,
    user: &mut ARTUserAgent,
    f_run: F1,
    f_rev: F2,
) -> Duration
where
    F1: Fn(&mut ARTUserAgent) -> (),
    F2: Fn(&mut ARTUserAgent) -> (),
{
    let mut revert_time = Duration::new(0, 0);
    let start = Instant::now();
    for _i in 0..iters {
        // black_box(user_agent1.remove_node(user_agent2.public_key()).unwrap());
        black_box(f_run(user));

        let start_revert = Instant::now();
        f_rev(user);
        revert_time += start_revert.elapsed();
    }
    start.elapsed() - revert_time
}

pub fn compute_art_and_ciphertexts_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ARTTrustedAgent: compute_art_and_ciphertexts");
    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);

                let mut art_agent =
                    ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());

                b.iter(|| art_agent.compute_art_and_ciphertexts(&members))
            },
        );
    }

    group.finish();
}

pub fn art_serialise_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ART");

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("serialise", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);

                let mut art_agent =
                    ARTTrustedAgent::new(ibbe.msk.clone().unwrap(), ibbe.pk.clone());
                let (tree, _, _) = art_agent.compute_art_and_ciphertexts(&members);

                b.iter(|| tree.serialise())
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("deserialize", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);

                let mut art_agent = ARTTrustedAgent::from(&ibbe);
                let (mut tree, _, _) = art_agent.compute_art_and_ciphertexts(&members);
                let art_json = tree.serialise().unwrap();

                b.iter(|| ART::from_json(&art_json))
            },
        );
    }

    group.finish();
}

pub fn art_user_agent_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ARTUserAgent");

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("new", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let (user_index, _, user_sk_id) = tools::sample_user_identity(&ibbe, &members);

                let mut art_agent = ARTTrustedAgent::from(&ibbe);
                let (mut tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

                b.iter(|| ARTUserAgent::new(tree.clone(), ciphertexts[user_index], user_sk_id))
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("update_key", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let (user_index, _, user_sk_id) = tools::sample_user_identity(&ibbe, &members);

                let mut art_agent = ARTTrustedAgent::from(&ibbe);
                let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

                let mut user_agent = ARTUserAgent::new(tree, ciphertexts[user_index], user_sk_id);

                b.iter(|| user_agent.update_key().unwrap())
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after update_key", group_size),
            group_size,
            |b, &group_size| {
                let (mut user_agent1, mut user_agent2) = get_two_user_agents(group_size);

                let (_, changes) = user_agent1.update_key().unwrap();

                b.iter(|| user_agent2.update_branch(&changes))
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("remove_node", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let samples =
                    tools::get_subset_of_user_identities(2, &ibbe, &members[0..4].to_vec())
                        .unwrap();

                let mut art_agent = ARTTrustedAgent::from(&ibbe);
                let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

                let mut user_agent1 = ARTUserAgent::new(
                    tree.clone(),
                    ciphertexts[samples[0].index],
                    samples[0].sk_id,
                );
                let mut user_agent2 =
                    ARTUserAgent::new(tree, ciphertexts[samples[1].index], samples[1].sk_id);

                b.iter_custom(move |iters| {
                    custom_iter_with_revert(
                        iters,
                        &mut user_agent1,
                        |mut agent| {
                            _ = ARTUserAgent::remove_node(&mut agent, user_agent2.public_key())
                        },
                        |mut agent| _ = ARTUserAgent::append_node(&mut agent, user_agent2.lambda),
                    )
                })
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after remove_node", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let samples =
                    tools::get_subset_of_user_identities(3, &ibbe, &members[0..4].to_vec())
                        .unwrap();

                let mut art_agent = ARTTrustedAgent::from(&ibbe);
                let (tree, ciphertexts, _) = art_agent.compute_art_and_ciphertexts(&members);

                let mut user_agent1 = ARTUserAgent::new(
                    tree.clone(),
                    ciphertexts[samples[0].index],
                    samples[0].sk_id,
                );
                let mut user_agent2 = ARTUserAgent::new(
                    tree.clone(),
                    ciphertexts[samples[1].index],
                    samples[1].sk_id,
                );
                let mut user_agent3 = ARTUserAgent::new(
                    tree.clone(),
                    ciphertexts[samples[2].index],
                    samples[2].sk_id,
                );

                let (_, remove_changes) =
                    user_agent1.remove_node(user_agent2.public_key()).unwrap();
                let (_, append_changes) = user_agent1.append_node(user_agent2.lambda).unwrap();

                // b.iter(|| user_agent2.update_branch(&changes))
                b.iter_custom(move |iters| {
                    custom_iter_with_revert(
                        iters,
                        &mut user_agent3,
                        |mut agent| _ = ARTUserAgent::update_branch(&mut agent, &remove_changes),
                        |mut agent| _ = ARTUserAgent::update_branch(&mut agent, &append_changes),
                    )
                })
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("make_temporal", group_size),
            group_size,
            |b, &group_size| {
                let (mut user_agent1, mut user_agent2) = get_two_user_agents(group_size);

                // b.iter(|| user_agent1.make_temporal(user_agent2.public_key()).unwrap())
                b.iter_custom(move |iters| {
                    custom_iter_with_revert(
                        iters,
                        &mut user_agent1,
                        |mut agent| {
                            _ = ARTUserAgent::make_temporal(&mut agent, user_agent2.public_key())
                        },
                        |mut agent| _ = ARTUserAgent::append_node(&mut agent, user_agent2.lambda),
                    )
                })
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after make_temporal", group_size),
            group_size,
            |b, &group_size| {
                let mut users = get_several_user_agents(group_size, 3);
                let mut user1 = users.pop().unwrap();
                let mut user2 = users.pop().unwrap();
                let mut user3 = users.pop().unwrap();

                let (_, make_temporal_changes) = user1.make_temporal(user2.public_key()).unwrap();
                let (_, append_changes) = user1.append_node(user2.lambda).unwrap();

                // b.iter(|| user_agent2.update_branch(&changes))
                b.iter_custom(move |iters| {
                    custom_iter_with_revert(
                        iters,
                        &mut user3,
                        |mut agent| {
                            _ = ARTUserAgent::update_branch(&mut agent, &make_temporal_changes)
                        },
                        |mut agent| _ = ARTUserAgent::update_branch(&mut agent, &append_changes),
                    )
                })
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("append_node", group_size),
            group_size,
            |b, &group_size| {
                let mut agent = get_several_user_agents(group_size, 1).remove(0);

                let lambda = Fp12::<Fq12Config>::rand(&mut thread_rng());

                b.iter(|| agent.append_node(lambda));
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after append_node", group_size),
            group_size,
            |b, &group_size| {
                let mut agents = get_several_user_agents(group_size, 2);

                let lambda = Fp12::<Fq12Config>::rand(&mut thread_rng());
                let public_key = agents[0].tree.public_key_from_lambda(lambda);

                // b.iter(|| {
                //     let mut agents = get_several_user_agents(group_size, 2);
                //     let (_, changes) = agents[0].append_node(lambda).unwrap();
                //     agents[1].update_branch(&changes)
                // });
                let (_, append_changes) = agents[0].append_node(lambda).unwrap();
                let (_, make_temporal_changes) = agents[0].make_temporal(public_key).unwrap();

                let mut user = agents.remove(1);

                b.iter_custom(move |iters| {
                    custom_iter_with_revert(
                        iters,
                        &mut user,
                        |mut agent| _ = ARTUserAgent::update_branch(&mut agent, &append_changes),
                        |mut agent| {
                            _ = ARTUserAgent::update_branch(&mut agent, &make_temporal_changes)
                        },
                    )
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    art_user_agent_benchmark,
    art_serialise_benchmark,
    compute_art_and_ciphertexts_benchmark,
);
criterion_main!(benches);
