extern crate rand;
//extern crate rand_chacha;
extern crate curve25519_dalek;
extern crate merlin;
extern crate bulletproofs;

use curve25519_dalek::scalar::Scalar;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use bulletproofs::r1cs::LinearCombination;

use super::r1cs_utils::{AllocatedScalar,constrain_lc_with_scalar};

pub const MIMC_ROUNDS: usize = 322;
//pub const MIMC_ROUNDS: usize = 10;


pub fn mimc1(x: &Scalar, constants: &[Scalar]) -> Scalar {
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut x = x.clone();
    for i in 0..MIMC_ROUNDS {
        x += constants[i];
        x = x * x * x;
    }
    x
}

pub fn mimc2(
    xl: &Scalar,
    xr: &Scalar,
    constants: &[Scalar]
) -> Scalar
{
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..MIMC_ROUNDS {
        let tmp1 = xl + constants[i];
        let mut tmp2 = (tmp1 * tmp1) * tmp1;
        tmp2 += xr;
        xr = xl;
        xl = tmp2;
    }

    xl
}

pub fn mimc1_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: AllocatedScalar,
    mimc_rounds: usize,
    mimc_constants: &[Scalar],
    image: &Scalar
) -> Result<(), R1CSError> {
    let res_v = mimc1_hash::<CS>(cs, x.variable.into(), mimc_rounds, mimc_constants)?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}

pub fn mimc2_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: AllocatedScalar,
    right: AllocatedScalar,
    mimc_rounds: usize,
    mimc_constants: &[Scalar],
    image: &Scalar
) -> Result<(), R1CSError> {
    let res_v = mimc2_hash::<CS>(cs, left.variable.into(), right.variable.into(), mimc_rounds, mimc_constants)?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}

pub fn mimc1_hash<CS: ConstraintSystem>(cs: &mut CS,
                                         x: LinearCombination,
                                         mimc_rounds: usize,
                                         mimc_constants: &[Scalar]) -> Result<LinearCombination, R1CSError> {
    let mut x_v = x;

    for j in 0..mimc_rounds {
        // x := (x + Cj)^3
        //let cs = &mut cs.namespace(|| format!("mimc round {}", j));

        let const_lc: LinearCombination = vec![(Variable::One(), mimc_constants[j])].iter().collect();

        let x_plus_const: LinearCombination = x_v.clone() + const_lc;

        let (l, _, l_sqr) = cs.multiply(x_plus_const.clone(), x_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        x_v = l_cube.into();
    }
    Ok(x_v)
}

pub fn mimc2_hash<CS: ConstraintSystem>(cs: &mut CS,
                                         left: LinearCombination,
                                         right: LinearCombination,
                                         mimc_rounds: usize,
                                         mimc_constants: &[Scalar]) -> Result<LinearCombination, R1CSError> {
    let mut left_v = left;
    let mut right_v = right;

    for j in 0..mimc_rounds {
        // xL, xR := xR + (xL + Ci)^3, xL
        //let cs = &mut cs.namespace(|| format!("mimc round {}", j));

        let const_lc: LinearCombination = vec![(Variable::One(), mimc_constants[j])].iter().collect();

        let left_plus_const: LinearCombination = left_v.clone() + const_lc;
        
        let (l, _, l_sqr) = cs.multiply(left_plus_const.clone(), left_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        let tmp = LinearCombination::from(l_cube) + right_v;
        right_v = left_v;
        left_v = tmp;
    }
    Ok(left_v)
}


#[cfg(test)]
mod tests {
    use super::*;
    // For benchmarking
    use std::time::{Duration, Instant};
    //use rand_chacha::ChaChaRng;
    use rand::SeedableRng;
    use super::rand::rngs::StdRng;

    #[test]
    fn test_mimc1() {
        let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
        //let constants = (0..MIMC_ROUNDS).map(|i| Scalar::one()).collect::<Vec<_>>();

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(1024, 1);

        const SAMPLES: u32 = 1;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..SAMPLES {
            // Generate a random preimage and compute the image
            let xl = Scalar::random(&mut test_rng);

            let image = mimc1(&xl, &constants);

            let (proof, commitments) = {
                let mut prover_transcript = Transcript::new(b"MiMC");
                let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

                let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut test_rng));

                let left_alloc_scalar = AllocatedScalar {
                    variable: var_l,
                    assignment: Some(xl),
                };

                let start = Instant::now();
                assert!(mimc1_gadget(&mut prover,
                                    left_alloc_scalar,
                                    MIMC_ROUNDS,
                                    &constants,
                                    &image).is_ok());

                println!("For MiMC1 rounds {}, no of constraints is {:?}", &MIMC_ROUNDS, &prover.metrics() );

                let proof = prover.prove(&bp_gens).unwrap();
                total_proving += start.elapsed();

                (proof, (com_l))
            };

            let mut verifier_transcript = Transcript::new(b"MiMC");
            let mut verifier = Verifier::new(&mut verifier_transcript);
            let var_l = verifier.commit(commitments);

            let left_alloc_scalar = AllocatedScalar {
                variable: var_l,
                assignment: None,
            };

            let start = Instant::now();
            assert!(mimc1_gadget(&mut verifier,
                                left_alloc_scalar,

                                MIMC_ROUNDS,
                                &constants,
                                &image).is_ok());

            assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
            total_verifying += start.elapsed();
        }

        println!("Total proving time for {} samples: {:?} seconds", SAMPLES, total_proving);
        println!("Total verifying time for {} samples: {:?} seconds", SAMPLES, total_verifying);
    }


    #[test]
    fn test_mimc2() {
        let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

        // Generate the MiMC round constants
        let constants = (0..MIMC_ROUNDS).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
        //let constants = (0..MIMC_ROUNDS).map(|i| Scalar::one()).collect::<Vec<_>>();

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(2048, 1);

        const SAMPLES: u32 = 1;
        let mut total_proving = Duration::new(0, 0);
        let mut total_verifying = Duration::new(0, 0);

        for _ in 0..SAMPLES {
            // Generate a random preimage and compute the image
            let xl = Scalar::random(&mut test_rng);
            let xr = Scalar::random(&mut test_rng);
            let image = mimc2(&xl, &xr, &constants);

            let (proof, commitments) = {
                let mut prover_transcript = Transcript::new(b"MiMC");
                let mut prover = Prover::new(&pc_gens, &mut prover_transcript);


                let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut test_rng));
                let (com_r, var_r) = prover.commit(xr, Scalar::random(&mut test_rng));

                let left_alloc_scalar = AllocatedScalar {
                    variable: var_l,
                    assignment: Some(xl),
                };

                let right_alloc_scalar = AllocatedScalar {
                    variable: var_r,
                    assignment: Some(xr),
                };

                let start = Instant::now();
                assert!(mimc2_gadget(&mut prover,
                                    left_alloc_scalar,
                                    right_alloc_scalar,
                                    MIMC_ROUNDS,
                                    &constants,
                                    &image).is_ok());

                println!("For MiMC2 rounds {}, no of constraints is {:?}", &MIMC_ROUNDS, &prover.metrics() );

                let proof = prover.prove(&bp_gens).unwrap();
                total_proving += start.elapsed();

                (proof, (com_l, com_r))
            };

            let mut verifier_transcript = Transcript::new(b"MiMC");
            let mut verifier = Verifier::new(&mut verifier_transcript);
            let var_l = verifier.commit(commitments.0);
            let var_r = verifier.commit(commitments.1);

            let left_alloc_scalar = AllocatedScalar {
                variable: var_l,
                assignment: None,
            };

            let right_alloc_scalar = AllocatedScalar {
                variable: var_r,
                assignment: None,
            };

            let start = Instant::now();
            assert!(mimc2_gadget(&mut verifier,
                                left_alloc_scalar,
                                right_alloc_scalar,
                                MIMC_ROUNDS,
                                &constants,
                                &image).is_ok());

            assert!(verifier.verify(&proof, &pc_gens, &bp_gens).is_ok());
            total_verifying += start.elapsed();
        }

        println!("Total proving time for {} samples: {:?} seconds", SAMPLES, total_proving);
        println!("Total verifying time for {} samples: {:?} seconds", SAMPLES, total_verifying);
    }

}