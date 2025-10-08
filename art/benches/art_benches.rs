use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{UniformRand, rand::SeedableRng, rand::prelude::StdRng};
use cortado::{CortadoAffine, Fr};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand::Rng;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use zrt_art::{
    errors::ARTError,
    traits::{ARTPrivateAPI, ARTPrivateView},
    types::{PrivateART, PublicART},
};

// hardcoded number of leaves in a tree for testing
// pub const TEST_SAMPLES: [usize; 4] = [16, 64, 256, 1024];
pub const TEST_SAMPLES: [usize; 2] = [16, 64];

pub fn get_two_private_arts<G>(
    secrets: &Vec<G::ScalarField>,
    tree: &PublicART<G>,
) -> Result<(PrivateART<G>, PrivateART<G>), ARTError>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    let user_agent1 = PrivateART::from_public_art_and_secret(tree.clone(), secrets[0])?;
    let user_agent2 = PrivateART::from_public_art_and_secret(tree.clone(), secrets[1])?;

    Ok((user_agent1, user_agent2))
}

pub fn get_several_private_arts<G>(
    number_of_agents: usize,
    secrets: &Vec<G::ScalarField>,
    tree: &PublicART<G>,
) -> Result<Vec<PrivateART<G>>, ARTError>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    let mut agents = Vec::new();
    for i in 0..number_of_agents {
        agents.push(PrivateART::from_public_art_and_secret(tree.clone(), secrets[i])?);
    }

    Ok(agents)
}

pub fn iter_with_revert<G, F1, F2>(
    iters: u64,
    user: &mut PrivateART<G>,
    f_run: F1,
    f_rev: F2,
) -> Duration
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
    F1: Fn(&mut PrivateART<G>) -> (),
    F2: Fn(&mut PrivateART<G>) -> (),
{
    let mut revert_time = Duration::new(0, 0);
    let start = Instant::now();
    for _i in 0..iters {
        black_box(f_run(user));

        let start_revert = Instant::now();
        f_rev(user);
        revert_time += start_revert.elapsed();
    }
    start.elapsed() - revert_time
}

pub fn art_creation_time_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("PublicART creation time from secrets");
    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(group_size),
            group_size,
            |b, &group_size| {
                let secrets = create_random_secrets(group_size);

                b.iter(|| PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator()))
            },
        );
    }

    group.finish();
}

pub fn art_serialisation_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ART serialisation");

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("Serialise", group_size),
            group_size,
            |b, &group_size| {
                let secrets = create_random_secrets(group_size);
                let tree = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
                    .unwrap()
                    .0;

                b.iter(|| tree.serialize())
            },
        );
    }

    for group_size in TEST_SAMPLES.iter() {
        group.throughput(Throughput::Elements(*group_size as u64));
        group.bench_with_input(
            BenchmarkId::new("Deserialize", group_size),
            group_size,
            |b, &group_size| {
                let secrets = create_random_secrets(group_size);
                let tree = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
                    .unwrap()
                    .0;
                let serialized = tree.serialize().unwrap();

                b.iter(|| PublicART::<CortadoAffine>::deserialize(&serialized))
            },
        );
    }

    group.finish();
}

pub fn art_operations_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Operation");
    let mut rng = StdRng::seed_from_u64(rand::random());

    // Create the same set of arts for all operations benchmark for every group size.
    let mut trees = Vec::new();
    let mut trees_secrets = Vec::new();
    for group_size in TEST_SAMPLES.iter() {
        let secrets = create_random_secrets(*group_size);
        let tree = PublicART::new_art_from_secrets(&secrets, &CortadoAffine::generator())
            .unwrap()
            .0;

        trees.push(tree);
        trees_secrets.push(secrets);
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("Clone + From private ART", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                b.iter(|| {
                    PrivateART::from_public_art_and_secret(trees[i].clone(), trees_secrets[i][0]).unwrap()
                })
            },
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));

        let mut public_art =
            PrivateART::from_public_art_and_secret(trees[i].clone(), trees_secrets[i][0]).unwrap();

        /// Key update
        let secret = Fr::rand(&mut rng);
        group.bench_with_input(
            BenchmarkId::new("update_key", TEST_SAMPLES[i]),
            &secret,
            |b, secret| b.iter(|| public_art.update_key(&secret).unwrap()),
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after update_key", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                let (mut private_art1, mut private_art2) =
                    get_two_private_arts(&trees_secrets[i], &trees[i]).unwrap();

                let secret = Fr::rand(&mut rng);
                let (_, changes, _) = private_art1.update_key(&secret).unwrap();

                b.iter(|| private_art2.update_private_art(&changes))
            },
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("make_blank", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                let (mut private_art1, private_art2) =
                    get_two_private_arts::<CortadoAffine>(&trees_secrets[i], &trees[i]).unwrap();

                b.iter_custom(move |iters| {
                    iter_with_revert(
                        iters,
                        &mut private_art1,
                        |private_art| {
                            _ = private_art.make_blank(
                                &private_art2.get_node_index().get_path().unwrap(),
                                &Fr::rand(&mut StdRng::seed_from_u64(rand::random())),
                            );
                        },
                        |mut private_art| {
                            _ = PrivateART::append_or_replace_node(
                                &mut private_art,
                                &private_art2.get_secret_key(),
                            )
                        },
                    )
                })
            },
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after make_temporal", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                let mut private_arts =
                    get_several_private_arts::<CortadoAffine>(3, &trees_secrets[i], &trees[i])
                        .unwrap();
                let mut private_art1 = private_arts.pop().unwrap();
                let private_art2 = private_arts.pop().unwrap();
                let mut private_art3 = private_arts.pop().unwrap();

                let (_, make_blank_changes, _) = private_art1
                    .make_blank(
                        &private_art2.get_node_index().get_path().unwrap(),
                        &Fr::rand(&mut StdRng::seed_from_u64(rand::random())),
                    )
                    .unwrap();
                let (_, append_changes, _) = private_art1
                    .append_or_replace_node(&private_art2.get_secret_key())
                    .unwrap();

                b.iter_custom(move |iters| {
                    iter_with_revert(
                        iters,
                        &mut private_art3,
                        |art| _ = art.update_private_art(&make_blank_changes),
                        |art| _ = art.update_private_art(&append_changes),
                    )
                })
            },
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("append_node", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                let mut private_art =
                    get_several_private_arts::<CortadoAffine>(1, &trees_secrets[i], &trees[i])
                        .unwrap()
                        .remove(0);

                let lambda = Fr::rand(&mut StdRng::seed_from_u64(rand::random()));

                b.iter(|| private_art.append_or_replace_node(&lambda));
            },
        );
    }

    for i in 0..TEST_SAMPLES.len() {
        group.throughput(Throughput::Elements(TEST_SAMPLES[i] as u64));
        group.bench_with_input(
            BenchmarkId::new("update_branch after append_node", TEST_SAMPLES[i]),
            &i,
            |b, &i| {
                let mut private_arts =
                    get_several_private_arts::<CortadoAffine>(2, &trees_secrets[i], &trees[i])
                        .unwrap();

                let lambda = Fr::rand(&mut StdRng::seed_from_u64(rand::random()));
                let public_key = private_arts[0].node_index.get_path().unwrap();

                let (_, append_changes, _) =
                    private_arts[0].append_or_replace_node(&lambda).unwrap();
                let (_, make_blank_changes, _) = private_arts[0]
                    .make_blank(&public_key, &Fr::rand(&mut rng))
                    .unwrap();

                let mut art = private_arts.remove(1);

                b.iter_custom(move |iters| {
                    iter_with_revert(
                        iters,
                        &mut art,
                        |mut art| _ = PrivateART::update_private_art(&mut art, &append_changes),
                        |mut art| _ = PrivateART::update_private_art(&mut art, &make_blank_changes),
                    )
                })
            },
        );
    }

    group.finish();
}

fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
    let mut rng = &mut StdRng::seed_from_u64(rand::random());

    (0..size).map(|_| F::rand(&mut rng)).collect()
}

criterion_group!(
    benches,
    art_operations_benchmark,
    art_serialisation_benchmark,
    art_creation_time_benchmark,
);
criterion_main!(benches);
