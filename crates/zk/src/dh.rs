#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Instant;

use rand_core::{le, OsRng};
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
use tracing_subscriber::field::debug;
use crate::curve::cortado::{self, CortadoAffine, Parameters, ToScalar};
use hex::FromHex;


const MODULUS_BIT_SIZE: u64 = 254;

pub fn acc<
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
    let x_acc: LinearCombination = acc(&x_bits, Scalar::from(2u64));
    cs.constrain(x.clone() - x_acc);

    Ok(x_bits)
}

// sketch1: Q_a=[λ_a]P1 ∈ G1, Com((λ_a, r), (Q_b, H2)) = [λ_a]Q_b + [r]H2 ∈ G2, λ_ab=x([λ_a]Q_b), Com((λ_ab, t), (P1, H1)), Q_ab=[λ_ab]P2
// sketch2: Com((λ_a, r), (P1, H1)) ∈ G1, check if DL equal across Com, Q_a; Q_b, Q_ab ∈ G2: compute λ_ab=x([λ_a]Q_B) => check Q_ab==[λ_ab]P2
// we use https://eprint.iacr.org/2022/1593.pdf to prove that λ_a is equal across G1, G2 (generalization of Chaum-Pedersen proto (G1=G2))

// proof of x(Q_ab) = x([λ_a]Q_b), idea from https://eprint.iacr.org/archive/2024/397/20240622:224417
pub fn dh_gadget_v1<CS: ConstraintSystem>(
    cs: &mut CS,
    λ_a: Option<Scalar>,
    Q_b: CortadoAffine,
    var_a: Variable,
    var_ab: Variable,
) -> Result<(), R1CSError> {
    let (w_a, w_b) = ( cortado::Parameters::COEFF_A.into_scalar(), cortado::Parameters::COEFF_B.into_scalar());
    let l = (MODULUS_BIT_SIZE) as i32;
    let Δ1: Vec<_> = (0..l).map(|i| if i == (l-1) {
        (cortado::Parameters::GENERATOR * cortado::Fr::from(-(l*l + l - 2)/2)).into_affine()
    } else {
        (cortado::Parameters::GENERATOR * cortado::Fr::from(i+2)).into_affine()
    }).collect();

    let mut δ = vec![Q_b];
    for _ in 1..l as usize {
        δ.push(((*δ.last().unwrap()) * cortado::Fr::from(2)).into_affine());
    }
    let Δ2: Vec<_> = Δ1.iter().zip(δ.iter()).map(|(x, y)| (*x+y).into_affine()).collect();
    let k_vars = bin_equality_gadget(cs, &LinearCombination::from(var_a), λ_a)?;
    
    // P_0 = Δ_0
    let (_, _, x0) = cs.multiply( Variable::One() * Δ1[0].x().unwrap().into_scalar() + k_vars[0] * (Δ2[0].x().unwrap() - Δ1[0].x().unwrap()).into_scalar(), Variable::One().into()); // x0 = k[0]*(x-x')+x'
    let (_, _, y0) = cs.multiply(Variable::One() * Δ1[0].y().unwrap().into_scalar() + k_vars[0] * (Δ2[0].y().unwrap() - Δ1[0].y().unwrap()).into_scalar(), Variable::One().into()); // y0 = k[0]*(y-y')+y'
    let mut P  = λ_a.map(|λ_a| vec![ (Q_b * cortado::Fr::from(λ_a.get_bit(0) as u64) + Δ1[0] ).into_affine() ] );
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
    cs.constrain(var_ab - P_vars.last().unwrap().0 );
    
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Witness {
    pub P_i: CortadoAffine,
    pub Δ_i: CortadoAffine,
    pub P_i_1: CortadoAffine,
    pub s_i: Scalar,
}

// proof based on https://eprint.iacr.org/archive/2024/397/20250504:183956
pub fn dh_gadget_v2<CS: ConstraintSystem>(
    cs: &mut CS,
    λ_a: Option<Scalar>,
    Q_b: CortadoAffine,
    var_a: Variable,
    var_ab: Variable,
) -> Result<(), R1CSError> {
    let l = (MODULUS_BIT_SIZE) as i32;
    let Δ1: Vec<_> = (0..l).map(|i| if i == (l-1) {
        (cortado::Parameters::GENERATOR * cortado::Fr::from(-(l*l + l - 2)/2)).into_affine()
    } else {
        (cortado::Parameters::GENERATOR * cortado::Fr::from(i+2)).into_affine()
    }).collect();

    let mut δ = vec![Q_b];
    for _ in 1..l as usize {
        δ.push(((*δ.last().unwrap()) * cortado::Fr::from(2)).into_affine());
    }
    let Δ2: Vec<_> = Δ1.iter().zip(δ.iter()).map(|(x, y)| (*x+y).into_affine()).collect();
    let k_vars = bin_equality_gadget(cs, &LinearCombination::from(var_a), λ_a)?;
    
    // P_0 = Δ_0
    let (_, _, x0) = cs.multiply( Variable::One() * Δ1[0].x().unwrap().into_scalar() + k_vars[0] * (Δ2[0].x().unwrap() - Δ1[0].x().unwrap()).into_scalar(), Variable::One().into()); // x0 = k[0]*(x-x')+x'
    let (_, _, y0) = cs.multiply(Variable::One() * Δ1[0].y().unwrap().into_scalar() + k_vars[0] * (Δ2[0].y().unwrap() - Δ1[0].y().unwrap()).into_scalar(), Variable::One().into()); // y0 = k[0]*(y-y')+y'
    let mut P_vars = vec![(x0, y0)];

    let mut P  = λ_a.map(|λ_a| vec![ (Q_b * cortado::Fr::from(λ_a.get_bit(0) as u64) + Δ1[0] ).into_affine() ] );
    
    for i in 1..l as usize {
        // calculate witness P_i = P_i_1 + Δ_i
        let w = λ_a.map(|λ_a| {
            let P_i_1 = *(P.as_ref().unwrap().last().unwrap());
            let P_i = (P_i_1 + match λ_a.get_bit(i) {
                true => Δ2[i],
                false => Δ1[i]
            }).into_affine();
            let Δ_i = if λ_a.get_bit(i) {
                Δ2[i]
            } else {
                Δ1[i]
            };
            P.as_mut().unwrap().push( P_i );
            let s_i = (P_i_1.y().unwrap().into_scalar() - Δ_i.y().unwrap().into_scalar()) * (P_i_1.x().unwrap().into_scalar() - Δ_i.x().unwrap().into_scalar()).invert();

            Witness {P_i_1, P_i, Δ_i, s_i}
        });

        let (Δ_i_x, Δ_i_y) = (
            Variable::One() * Δ1[i].x().unwrap().into_scalar() + k_vars[i] * (Δ2[i].x().unwrap() - Δ1[i].x().unwrap()).into_scalar(), 
            Variable::One() * Δ1[i].y().unwrap().into_scalar() + k_vars[i] * (Δ2[i].y().unwrap() - Δ1[i].y().unwrap()).into_scalar()
        );

        let (_, s_i, s_i_2) = cs.allocate_multiplier(w.as_ref().map(|w| (w.s_i, w.s_i)))?;
        let x_P = cs.allocate(w.as_ref().map(|w| w.P_i.x().unwrap().into_scalar()))?;
        let y_P = cs.allocate(w.as_ref().map(|w| w.P_i.y().unwrap().into_scalar()))?;
        let (P_i_1_x, P_i_1_y) = *P_vars.last().unwrap();
        P_vars.push((x_P, y_P));
        
        cs.constrain(s_i_2 - x_P - P_i_1_x - Δ_i_x.clone());

        // check that Δ_i, -P_i, P_i_1 is on the same line
        let (_, _, t1) = cs.multiply(Scalar::ONE * s_i, P_i_1_x - Δ_i_x);
        cs.constrain(t1 - (P_i_1_y - Δ_i_y));
        let (_, _, t2) = cs.multiply(Scalar::ONE * s_i, P_i_1_x - x_P);
        cs.constrain(t2 - (P_i_1_y + y_P));
    }
    debug!("P_final = {:?}", P.as_ref().map(|P| P.iter().last().clone() ));
    // final check of x coordinate
    cs.constrain(var_ab - P_vars.last().unwrap().0 );
    
    Ok(())
}

#[instrument(skip(pc_gens, bp_gens, Q_b, λ_a, λ_ab))]
pub fn dh_gadget_proof(
    ver: u8,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    Q_b: CortadoAffine,

    λ_a: Scalar,
    λ_ab: Scalar,
) -> Result<(R1CSProof, (CompressedRistretto, CompressedRistretto)), R1CSError> {
    let mut blinding_rng = thread_rng();

    let mut transcript = Transcript::new(b"DHGadget");

    // 1. Create a prover
    let mut prover = Prover::new(pc_gens, &mut transcript);
    // 2. Commit high-level variables
    let (a_commitment, var_a) = prover.commit(λ_a, Scalar::random(&mut blinding_rng));
    let (ab_commitment, var_ab) = prover.commit(λ_ab, Scalar::random(&mut blinding_rng));
    let mut start = Instant::now();
    match ver {
        1 => dh_gadget_v1(&mut prover, Some(λ_a), Q_b, var_a, var_ab)?,
        2 => dh_gadget_v2(&mut prover, Some(λ_a), Q_b, var_a, var_ab)?,
        _ => return Err(R1CSError::VerificationError),
    }
    debug!("DHGadget prover synthetize time: {:?}, metrics: {:?}", start.elapsed(), prover.metrics());
    start = Instant::now();
    let proof = prover.prove(bp_gens)?;
    debug!("DHGadget proving time: {:?}, proof_size = {:?}", start.elapsed(), proof.to_bytes().len() );

    Ok((proof, (a_commitment, ab_commitment)))
}

#[instrument(skip(pc_gens, bp_gens, proof, a_commitment, ab_commitment))]
pub fn dh_gadget_verify(
    ver: u8,
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    proof: R1CSProof,
    Q_b: CortadoAffine,

    a_commitment: CompressedRistretto,
    ab_commitment: CompressedRistretto,
) -> Result<(), R1CSError> {
    let mut transcript = Transcript::new(b"DHGadget");
    let mut verifier = Verifier::new(&mut transcript);
    let var_a = verifier.commit(a_commitment);
    let var_ab = verifier.commit(ab_commitment);
    let mut start = Instant::now();
    match ver {
        1 => dh_gadget_v1(&mut verifier, None, Q_b, var_a, var_ab)?,
        2 => dh_gadget_v2(&mut verifier, None, Q_b, var_a, var_ab)?,
        _ => return Err(R1CSError::VerificationError),
    }
    debug!("DHGadget verifier synthetize time: {:?}", start.elapsed());
    start = Instant::now();
    let r = verifier
        .verify(&proof, &pc_gens, &bp_gens)
        .map_err(|_| R1CSError::VerificationError);
    debug!("DHGadget verification time: {:?}", start.elapsed());
    r
}

pub fn dh_gadget_roundtrip(ver: u8) -> Result<(), R1CSError> {
    let mut blinding_rng = rand::thread_rng();
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(2048, 1);

    let r: cortado::Fr = blinding_rng.r#gen();
    let Q_b = (CortadoAffine::generator() * r).into_affine();
    let λ_a: cortado::Fr = blinding_rng.r#gen();
    
    let R = (Q_b * λ_a).into_affine();
    debug!("R_real={:?}", R);
    
    let (proof, (var_a, var_b)) = dh_gadget_proof(
        ver, 
        &pc_gens, 
        &bp_gens, Q_b, 
        Scalar::from_bytes_mod_order((&λ_a.into_bigint().to_bytes_le()[..]).try_into().unwrap()), 
        R.x().unwrap().into_scalar() 
    )?;

    dh_gadget_verify(ver, &pc_gens, &bp_gens, proof, Q_b, var_a, var_b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_serialize::CanonicalDeserialize;
    use rand::thread_rng;

    #[test]
    fn dh_gadget_roundtrip_v1() {
        assert!(dh_gadget_roundtrip(1).is_ok());
    }

    #[test]
    fn dh_gadget_roundtrip_v2() {
        assert!(dh_gadget_roundtrip(2).is_ok());
    }
}