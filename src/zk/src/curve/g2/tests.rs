use crate::curve::g2::{Fq, Fr, G2Projective};
use ark_algebra_test_templates::{test_field, test_group};

test_field!(fq; Fq; mont_prime_field);
test_field!(fr; Fr; mont_prime_field);
test_group!(g2; G2Projective);
