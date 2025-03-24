#![allow(non_snake_case)]
use std::ops::{Add, Mul};

use rand_core::OsRng;
use ark_serialize::Valid;
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use tracing::{debug, info, instrument};
use ark_ec::{short_weierstrass::SWCurveConfig, AffineRepr, CurveGroup};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use zk::curve::g2::{self as G2, ToScalar};
use hex::FromHex;

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn range_proof<CS: ConstraintSystem>(
    cs: &mut CS,
    mut v: LinearCombination,
    v_assignment: Option<u64>,
    n: usize,
) -> Result<(), R1CSError> {
    let mut exp_2 = Scalar::ONE;
    for i in 0..n {
        // Create low-level variables and add them to constraints
        let (a, b, o) = cs.allocate_multiplier(v_assignment.map(|q| {
            let bit: u64 = (q >> i) & 1;
            ((1 - bit).into(), bit.into())
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        v = v - b * exp_2;

        exp_2 = exp_2 + exp_2;
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.constrain(v);

    Ok(())
}

#[test]
fn range_proof_gadget() {
    use rand::thread_rng;
    use rand::Rng;

    let mut rng = thread_rng();
    let m = 3; // number of values to test per `n`

    for n in [2, 10, 32, 63].iter() {
        let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
        let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min..max)).collect();
        for v in values {
            assert!(range_proof_helper(v.into(), *n).is_ok());
        }
        assert!(range_proof_helper((max + 1).into(), *n).is_err());
    }
}

fn range_proof_helper(v_val: u64, n: usize) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    debug!("begin range proof");
    // Prover's scope
    let (proof, commitment) = {
        // Prover makes a `ConstraintSystem` instance representing a range proof gadget
        let mut prover_transcript = Transcript::new(b"RangeProofTest");
        let mut rng = rand::thread_rng();

        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (com, var) = prover.commit(v_val.into(), Scalar::random(&mut rng));
        assert!(range_proof(&mut prover, var.into(), Some(v_val), n).is_ok());

        let proof = prover.prove(&bp_gens)?;

        (proof, com)
    };
    debug!("end range prooving");
    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"RangeProofTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let var = verifier.commit(commitment);

    // Verifier adds constraints to the constraint system
    assert!(range_proof(&mut verifier, var.into(), None, n).is_ok());

    // Verifier verifies proof
    let v = verifier.verify(&proof, &pc_gens, &bp_gens);
    debug!("verify range proof");
    v
}


/// Constrains (a1 + a2) * (b1 + b2) = (c1 + c2)
fn example_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    a1: LinearCombination,
    a2: LinearCombination,
    b1: LinearCombination,
    b2: LinearCombination,
    c1: LinearCombination,
    c2: LinearCombination,
) {
    let (_, _, c_var) = cs.multiply(a1 + a2, b1 + b2);
    cs.constrain(c1 + c2 - c_var);
}

// Prover's scope
fn example_gadget_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);

    // 2. Commit high-level variables
    let (commitments, vars): (Vec<_>, Vec<_>) = [a1, a2, b1, b2, c1]
        .into_iter()
        .map(|x| prover.commit(Scalar::from(x), Scalar::random(&mut thread_rng())))
        .unzip();

    // 3. Build a CS
    example_gadget(
        &mut prover,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        Scalar::from(c2).into(),
    );

    // 4. Make a proof
    let proof = prover.prove(bp_gens)?;

    Ok((proof, commitments))
}

// Verifier logic
fn example_gadget_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    c2: u64,
    proof: R1CSProof,
    commitments: Vec<CompressedRistretto>,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"R1CSExampleGadget");

    // 1. Create a verifier
    let mut verifier = Verifier::new(&mut transcript);

    // 2. Commit high-level variables
    let vars: Vec<_> = commitments.iter().map(|V| verifier.commit(*V)).collect();

    // 3. Build a CS
    example_gadget(
        &mut verifier,
        vars[0].into(),
        vars[1].into(),
        vars[2].into(),
        vars[3].into(),
        vars[4].into(),
        Scalar::from(c2).into(),
    );

    // 4. Verify the proof
    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError)
}

fn example_gadget_roundtrip_helper(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

    example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
}

fn example_gadget_roundtrip_serialization_helper(
    a1: u64,
    a2: u64,
    b1: u64,
    b2: u64,
    c1: u64,
    c2: u64,
) -> Result<(), R1CSError> {
    // Common
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);

    let (proof, commitments) = example_gadget_proof(&pc_gens, &bp_gens, a1, a2, b1, b2, c1, c2)?;

    let proof = proof.to_bytes();

    let proof = R1CSProof::from_bytes(&proof)?;

    example_gadget_verify(&pc_gens, &bp_gens, c2, proof, commitments)
}

#[test]
fn example_gadget_test() {
    // (3 + 4) * (6 + 1) = (40 + 9)
    assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 9).is_ok());
    // (3 + 4) * (6 + 1) != (40 + 10)
    assert!(example_gadget_roundtrip_helper(3, 4, 6, 1, 40, 10).is_err());
}

#[test]
fn example_gadget_serialization_test() {
    // (3 + 4) * (6 + 1) = (40 + 9)
    assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 9).is_ok());
    // (3 + 4) * (6 + 1) != (40 + 10)
    assert!(example_gadget_roundtrip_serialization_helper(3, 4, 6, 1, 40, 10).is_err());
}


const MODULUS_BIT_SIZE: u64 = 254;

pub fn lakey_acc<
    U: Clone,
    V: Clone + Mul<Output = V>,
    T: From<U> + Add<Output = T> + Mul<V, Output = T> + Default + Clone,
>(
    x: &[U],
    base: V,
) -> T {
    let (head, tail) = (&x[0], &x[1..]);
    let init = T::from(head.clone());
    let mut a = base.clone();
    tail.iter().enumerate().fold(init, |acc, (i, xi)| {
        let acc = acc + T::from(xi.clone()) * a.clone();
        // Skip to prevent overflow.
        if i != tail.len() - 1 {
            a = a.clone() * base.clone();
        }
        acc
    })
}

trait GetBit {
    fn get_bit(&self, i: usize) -> bool;
}

impl GetBit for Scalar {
    fn get_bit(&self, i: usize) -> bool {
        (self.as_bytes()[i/8] >> (i%8)) & 1 == 1
    }
}
fn bin_equality_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: &LinearCombination,
    x_val: Option<Scalar>,
) -> Result<Vec<Variable>, R1CSError> {

    
    let x_bits: Vec<Variable> = (0..MODULUS_BIT_SIZE as usize)
        .map(|i| {
            // Create low-level variables and add them to constraints
            let (a, b, o) = cs.allocate_multiplier(x_val.map(|bint| {
                let bit = bint.get_bit(i) as u64;
                ((1 - bit).into(), bit.into())
            }))?;

            // Enforce a * b = 0, so one of (a,b) is zero
            cs.constrain(o.into());

            // Enforce that a = 1 - b, so they both are 1 or 0.
            cs.constrain(a + (b - Scalar::from(1u64)));

            Ok(b)
        })
        .collect::<Result<_, R1CSError>>()?;

    // Enforce that x = Sum(b_i * 2^i, i = 0..n-1)
    let x_acc: LinearCombination = lakey_acc(&x_bits, Scalar::from(2u64));
    cs.constrain(x.clone() - x_acc);

    Ok(x_bits)
}

// sketch1: Q_a=[λ_a]P1 ∈ G1, Com((λ_a, r), (Q_b, H2)) = [λ_a]Q_b + [r]H2 ∈ G2, λ_ab=x([λ_a]Q_b), Com((λ_ab, t), (P1, H1)), Q_ab=[λ_ab]P2
// sketch2: Com((λ_a, r), (P1, H1)) ∈ G1, check if DL equal across Com, Q_a; Q_b, Q_ab ∈ G2: compute λ_ab=x([λ_a]Q_B) => check Q_ab==[λ_ab]P2
// we use https://eprint.iacr.org/2022/1593.pdf to prove that λ_a is equal across G1, G2 (generalization of Chaum-Pedersen proto (G1=G2))

// proof of x(Q_ab) = x([λ_a]Q_b), idea from https://eprint.iacr.org/2024/397.pdf
fn dh_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    λ_a: Option<Scalar>,
    Q_b: G2::G2Affine,
    var_a: Variable,
    var_ab: Variable,
) -> Result<(), R1CSError> {
    let (w_a, w_b) = ( G2::Parameters::COEFF_A.into_scalar(), G2::Parameters::COEFF_B.into_scalar());
    let l = (MODULUS_BIT_SIZE) as i32;
    let Δ1: Vec<_> = (0..l).map(|i| if i == (l-1) {
        (G2::Parameters::GENERATOR*G2::Fr::from(-(l*l + l - 2)/2)).into_affine()
    } else {
        (G2::Parameters::GENERATOR*G2::Fr::from(i+2)).into_affine()
    }).collect();

    let mut δ = vec![Q_b];
    for _ in 1..l as usize {
        δ.push(((*δ.last().unwrap())*G2::Fr::from(2)).into_affine());
    }
    let Δ2: Vec<_> = Δ1.iter().zip(δ.iter()).map(|(x, y)| (*x+y).into_affine()).collect();
    let k_vars = bin_equality_gadget(cs, &LinearCombination::from(var_a), λ_a)?;
    
    // P_0 = Δ_0
    let (_, _, x0) = cs.multiply( Variable::One() * Δ1[0].x().unwrap().into_scalar() + k_vars[0] * (Δ2[0].x().unwrap() - Δ1[0].x().unwrap()).into_scalar(), Variable::One().into()); // x0 = k[0]*(x-x')+x'
    let (_, _, y0) = cs.multiply(Variable::One() * Δ1[0].y().unwrap().into_scalar() + k_vars[0] * (Δ2[0].y().unwrap() - Δ1[0].y().unwrap()).into_scalar(), Variable::One().into()); // y0 = k[0]*(y-y')+y'
    let mut P  = λ_a.map(|λ_a| vec![ (Q_b * G2::Fr::from(λ_a.get_bit(0) as u64) + Δ1[0] ).into_affine() ] );
    let mut P_vars = vec![(x0, y0)];
    
    for i in 1..l as usize {
        // calculate witness P_i = P_i_1 + Δ_i
        let P_i = if let Some(λ_a) = λ_a {
            let P_i = (*(P.as_ref().unwrap().last().unwrap()) + match λ_a.get_bit(i) {
                true => Δ2[i],
                false => Δ1[i]
            }).into_affine();
            P.as_mut().unwrap().push( P_i );
            Some(P_i)
        } else { None };

        let (Δ_i_x, Δ_i_y) = (
            Variable::One() * Δ1[i].x().unwrap().into_scalar() + k_vars[i] * (Δ2[i].x().unwrap() - Δ1[i].x().unwrap()).into_scalar(), 
            Variable::One() * Δ1[i].y().unwrap().into_scalar() + k_vars[i] * (Δ2[i].y().unwrap() - Δ1[i].y().unwrap()).into_scalar()
        );

        let (_, x_P, x_P2) = cs.allocate_multiplier(P_i.map(|P_i| (P_i.x().unwrap().into_scalar(), P_i.x().unwrap().into_scalar())))?;
        let (_, y_P, y_P2) = cs.allocate_multiplier(P_i.map(|P_i| (P_i.y().unwrap().into_scalar(), P_i.y().unwrap().into_scalar())))?;
        let (_, _, x_P3) = cs.multiply(x_P2.into(), x_P.into());
        let (P_i_1_x, P_i_1_y) = *P_vars.last().unwrap();
        P_vars.push((x_P, y_P));
        
        // check curve equation for current points
        //debug!("{:?} = {:?}", P_i.map(|P_i| P_i.x().unwrap().into_scalar() * P_i.x().unwrap().into_scalar() * P_i.x().unwrap().into_scalar() + w_a * P_i.x().unwrap().into_scalar() + w_b), P_i.map(| P_i| P_i.y().unwrap().into_scalar()));
        let curve_eq = y_P2 - x_P3 - x_P*w_a - w_b;
        cs.constrain(curve_eq);

        // check that Δ_i, -P_i, P_i_1 is on the same line
        let (_, _, t1) = cs.multiply(P_i_1_y + y_P, Δ_i_x - x_P);
        let (_, _, t2) = cs.multiply(Δ_i_y + y_P, P_i_1_x - x_P);
        cs.constrain(t1-t2);
    }
    info!("P_final = {:?}", P.as_ref().map(|P| P.iter().last().clone() ));
    // final check of x coordinate
    //cs.constrain(var_ab - P_vars.last().unwrap().0 );
    
    Ok(())
}

#[instrument(skip(pc_gens, bp_gens, Q_b, λ_a, λ_ab))]
fn dh_gadget_proof(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    Q_b: G2::G2Affine,

    λ_a: Scalar,
    λ_ab: Scalar,
) -> Result<(R1CSProof, (CompressedRistretto, CompressedRistretto)), R1CSError> {
    let mut blinding_rng = thread_rng();

    let mut transcript = Transcript::new(b"ARTGadget");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // 2. Commit high-level variables
    let (a_commitment, var_a) = prover.commit(λ_a, Scalar::random(&mut blinding_rng));
    let (ab_commitment, var_ab) = prover.commit(λ_ab, Scalar::random(&mut blinding_rng));

    dh_gadget(&mut prover, Some(λ_a), Q_b, var_a, var_ab)?;
    let circuit_len = prover.metrics();

    let proof = prover.prove(bp_gens)?;
    info!("ARTGadget proved: circuit_size = {:?}, proof_size = {:?}", circuit_len, proof.to_bytes().len() );

    Ok((proof, (a_commitment, ab_commitment)))
}

#[instrument(skip(pc_gens, bp_gens, proof, a_commitment, ab_commitment))]
fn dh_gadget_verify(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: R1CSProof,
    Q_b: G2::G2Affine,

    a_commitment: CompressedRistretto,
    ab_commitment: CompressedRistretto,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"ARTGadget");
    let mut verifier = Verifier::new(&mut transcript);
    let var_a = verifier.commit(a_commitment);
    let var_ab = verifier.commit(ab_commitment);

    dh_gadget(&mut verifier, None, Q_b, var_a, var_ab)?;

    verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError)
}

fn dh_gadget_roundtrip() -> Result<(), R1CSError> {
    let mut blinding_rng = rand::thread_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2048, 1);

    let r: G2::Fr = blinding_rng.r#gen();
    let Q_b = (G2::G2Affine::generator() * r).into_affine();

    let λ_a = BigInt::new([(1u64<<59) + 5, 1, 1, (1u64<<59) + 5]);
    
    let R = (Q_b * G2::Fr::from(λ_a)).into_affine();
    info!("R_real={:?}", R);
    
    let (proof, (var_a, var_b)) = dh_gadget_proof(&pc_gens, &bp_gens, Q_b, Scalar::from_bytes_mod_order( (&λ_a.to_bytes_le()[..]).try_into().unwrap() ), R.x().unwrap().into_scalar() )?;

    dh_gadget_verify(&pc_gens, &bp_gens, proof, Q_b, var_a, var_b)
}

fn main() {
    // Використовуємо змінну середовища MY_LOG_LEVEL замість RUST_LOG
    let log_level = std::env::var("PROOF_LOG").unwrap_or_else(|_| "debug".to_string());

    tracing_subscriber::fmt()
         // Встановлюємо рівень логування з змінної середовища
         .with_env_filter(log_level)
         // Додаємо вивід часу (опціонально)
         .with_target(false)
         .init();

    dh_gadget_roundtrip().unwrap();
}