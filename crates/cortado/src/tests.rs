// Unfortunately, arkworks has a bug for primes p=8k+5, tests run infinitely
/*
use crate::{fq::Fq, fr::Fr, cortado::CortadoProjective};
use ark_algebra_test_templates::{test_field, test_group};

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
test_group!(g2; CortadoProjective);
*/