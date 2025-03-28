use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use hibbe::ibbe_del7::{IBBEDel7, UserIdentity};
use hibbe::tools;
use rand::{thread_rng, Rng};

// pub const TEST_SAMPLES: [u32; 5] = [100, 200, 300, 400, 500];
pub const TEST_SAMPLES: [u32; 3] = [100, 200, 300];
pub const MESSAGE_SIZE: usize = 100;

pub fn ibbe_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("IBBEDel7");

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("setup", group_size),
            group_size,
            |b, &size| {
                b.iter(|| IBBEDel7::setup(size));
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("extract", group_size),
            group_size,
            |b, &group_size| {
                let ibbe = IBBEDel7::setup(group_size);
                let user_id = UserIdentity {
                    identity: String::from(thread_rng().gen_range(0..group_size).to_string()),
                };

                b.iter(|| ibbe.extract(&user_id).unwrap())
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("encrypt", group_size),
            group_size,
            |b, &group_size| {
                let ibbe = IBBEDel7::setup(group_size);
                let set_of_users = tools::crete_set_of_identities(group_size);

                b.iter(|| ibbe.encrypt(&set_of_users))
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("decrypt", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let (_, user, user_sk_id) = tools::sample_user_identity(&ibbe, &members);
                let (header, _) = ibbe.encrypt(&members);

                b.iter(|| ibbe.decrypt(&members, &user, &user_sk_id, &header))
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("sign", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let (_, _, user_sk_id) = tools::sample_user_identity(&ibbe, &members);

                let message = tools::gen_random_string(MESSAGE_SIZE);

                b.iter(|| ibbe.sign(&message, &user_sk_id))
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("verify", group_size),
            group_size,
            |b, &group_size| {
                let (ibbe, members) = tools::gen_ibbe_tool_box(group_size);
                let (_, user, user_sk_id) = tools::sample_user_identity(&ibbe, &members);

                let message = tools::gen_random_string(MESSAGE_SIZE);
                let sigma = ibbe.sign(&message, &user_sk_id);

                b.iter(|| ibbe.verify(&message, &sigma, &user))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, ibbe_benchmark,);
criterion_main!(benches);
