#![allow(non_snake_case)]
use std::ops::{Add, Mul};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{self, Instant};

use crate::gadgets::r1cs_utils::{AllocatedPoint, AllocatedScalar, nonzero_lc_gadget};
use ark_ec::{AffineRepr, CurveGroup, short_weierstrass::SWCurveConfig};
use ark_ff::{BigInt, BigInteger, Field, PrimeField, UniformRand};
use ark_serialize::Valid;
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::{ProofError, r1cs::*};
use cortado::{self, CortadoAffine, Parameters, ToScalar};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use hex::FromHex;
use merlin::Transcript;
use once_cell::sync::OnceCell;
use rand::seq::SliceRandom;
use rand::{Rng, thread_rng};
use rand_core::{OsRng, le};
use tracing::{debug, info, instrument, trace};
use tracing_subscriber::field::debug;

const MODULUS_BIT_SIZE: u64 = 254;
static S: OnceCell<Vec<CortadoAffine>> = OnceCell::new();

fn acc<
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
        (self.as_bytes()[i / 8] >> (i % 8)) & 1 == 1
    }
}

/// checks if x value belongs to the range [0, 2^bit_size)
pub fn bin_equality_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: &LinearCombination,
    x_val: Option<Scalar>,
    bit_size: u64,
) -> Result<Vec<Variable>, R1CSError> {
    let x_bits: Vec<Variable> = (0..bit_size as usize)
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

/// The number of bits of δ = ℓ - 2^252, where ℓ is the order of the scalars (2^124 < δ < 2^125).
const DELTA_BITS: usize = 125;

/// Enforces that the MODULUS_BIT_SIZE little-endian bits `k` of a scalar, as an integer
/// K = Sum(k_i * 2^i), are below ℓ.
///
/// `bin_equality_gadget` only checks the sum modulo ℓ, so with 254 bits K, K + ℓ, K + 2ℓ and
/// K + 3ℓ all decompose the same committed scalar. ℓ is not the order of Cortado, so these give
/// different points, and two scalar multiplications by one committed secret could use different
/// integers. With ℓ = 2^252 + δ, K < ℓ iff k_253 = 0 and, when k_252 = 1, k_125..k_251 are zero
/// and the low DELTA_BITS bits are at most δ - 1. Costs DELTA_BITS + 2 multipliers.
pub fn canonical_bits_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    k: &[Variable],
) -> Result<(), R1CSError> {
    assert_eq!(k.len(), MODULUS_BIT_SIZE as usize);

    cs.constrain(k[253].into());

    // k_252 * (k_125 + ... + k_251) = 0; a sum of at most 127 bits is zero only if all are
    let high: LinearCombination = k[DELTA_BITS..252]
        .iter()
        .map(|b| (*b, Scalar::ONE))
        .collect();
    let (_, _, high_if_top) = cs.multiply(k[252].into(), high);
    cs.constrain(high_if_top.into());

    // k_252 * (δ - 1 - low) is in [0, 2^DELTA_BITS): 0 when k_252 = 0, otherwise low ≤ δ - 1
    let mut low = LinearCombination::from(Scalar::ZERO);
    let mut pow = Scalar::ONE;
    for b in &k[..DELTA_BITS] {
        low = low + *b * pow;
        pow = pow + pow;
    }
    let mut two_pow_252 = [0u8; 32];
    two_pow_252[31] = 0x10;
    // δ - 1 = ℓ - 2^252 - 1, which is -2^252 - 1 modulo ℓ
    let delta_minus_one = -Scalar::from_bytes_mod_order(two_pow_252) - Scalar::ONE;
    let (_, _, slack) = cs.multiply(k[252].into(), Variable::One() * delta_minus_one - low);
    let slack_val = cs.eval(&LinearCombination::from(slack));
    bin_equality_gadget(
        cs,
        &LinearCombination::from(slack),
        slack_val,
        DELTA_BITS as u64,
    )?;

    Ok(())
}

// sketch1: Q_a=[λ_a]P1 ∈ G1, Com((λ_a, r), (Q_b, H2)) = [λ_a]Q_b + [r]H2 ∈ G2, λ_ab=x([λ_a]Q_b), Com((λ_ab, t), (P1, H1)), Q_ab=[λ_ab]P2
// sketch2: Com((λ_a, r), (P1, H1)) ∈ G1, check if DL equal across Com, Q_a; Q_b, Q_ab ∈ G2: compute λ_ab=x([λ_a]Q_B) => check Q_ab==[λ_ab]P2
// we use https://eprint.iacr.org/2022/1593.pdf to prove that λ_a is equal across G1, G2 (generalization of Chaum-Pedersen proto (G1=G2))

/// The bits of a committed scalar: decomposed once, with `bin_equality_gadget`, and
/// range-checked once, with `canonical_bits_gadget`, so that they are the bits of the one integer
/// below ℓ the commitment holds. Every scalar multiplication by that scalar in a circuit can walk
/// the same bits (`scalar_mul_bits_gadget`), instead of decomposing it again for 381 multipliers.
#[derive(Clone, Debug)]
pub struct ScalarBits {
    vars: Vec<Variable>,
    assignment: Option<Scalar>,
}

/// Decomposes and range-checks the bits of `x`, for `scalar_mul_bits_gadget`.
pub fn scalar_bits_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: AllocatedScalar,
) -> Result<ScalarBits, R1CSError> {
    let vars = bin_equality_gadget(
        cs,
        &LinearCombination::from(x.variable),
        x.assignment,
        MODULUS_BIT_SIZE,
    )?;
    canonical_bits_gadget(cs, &vars)?;
    Ok(ScalarBits {
        vars,
        assignment: x.assignment,
    })
}

/// gadget for scalar multiplication, returns constrainted variable R = λ_a * Q_b
/// based on https://eprint.iacr.org/archive/2024/397/20240622:224417
fn scalar_mul_bits_v1<CS: ConstraintSystem>(
    cs: &mut CS,
    k: &ScalarBits,
    Q_b: CortadoAffine,
) -> Result<AllocatedPoint, R1CSError> {
    let λ_a = k.assignment;
    let (w_a, w_b) = (
        cortado::Parameters::COEFF_A.into_scalar(),
        cortado::Parameters::COEFF_B.into_scalar(),
    );
    let l = (MODULUS_BIT_SIZE) as i32;
    let Δ1 = S.get_or_init(|| {
        let G = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);
        (0..l)
            .map(|i| {
                if i == (l - 1) {
                    (G * cortado::Fr::from(-(l * l + l - 2) / 2)).into_affine()
                } else {
                    (G * cortado::Fr::from(i + 2)).into_affine()
                }
            })
            .collect()
    });

    let mut δ = vec![Q_b];
    for _ in 1..l as usize {
        δ.push(((*δ.last().unwrap()) * cortado::Fr::from(2)).into_affine());
    }
    let Δ2: Vec<_> = Δ1
        .iter()
        .zip(δ.iter())
        .map(|(x, y)| (*x + y).into_affine())
        .collect();
    finite_table(&Q_b, &Δ2)?;
    let k_vars = &k.vars;

    // P_0 = Δ_0
    let (_, _, x0) = cs.multiply(
        Variable::One() * Δ1[0].x().unwrap().into_scalar()
            + k_vars[0] * (Δ2[0].x().unwrap() - Δ1[0].x().unwrap()).into_scalar(),
        Variable::One().into(),
    ); // x0 = k[0]*(x-x')+x'
    let (_, _, y0) = cs.multiply(
        Variable::One() * Δ1[0].y().unwrap().into_scalar()
            + k_vars[0] * (Δ2[0].y().unwrap() - Δ1[0].y().unwrap()).into_scalar(),
        Variable::One().into(),
    ); // y0 = k[0]*(y-y')+y'
    let mut P = λ_a
        .map(|λ_a| vec![(Q_b * cortado::Fr::from(λ_a.get_bit(0) as u64) + Δ1[0]).into_affine()]);
    let mut P_vars = vec![(x0, y0)];

    for i in 1..l as usize {
        // calculate witness P_i = P_i_1 + Δ_i
        let P_i = if let Some(λ_a) = λ_a {
            let P_i = (*(P.as_ref().unwrap().last().unwrap())
                + match λ_a.get_bit(i) {
                    true => Δ2[i],
                    false => Δ1[i],
                })
            .into_affine();
            P.as_mut().unwrap().push(P_i);
            Some(P_i)
        } else {
            None
        };

        let (Δ_i_x, Δ_i_y) = (
            Variable::One() * Δ1[i].x().unwrap().into_scalar()
                + k_vars[i] * (Δ2[i].x().unwrap() - Δ1[i].x().unwrap()).into_scalar(),
            Variable::One() * Δ1[i].y().unwrap().into_scalar()
                + k_vars[i] * (Δ2[i].y().unwrap() - Δ1[i].y().unwrap()).into_scalar(),
        );

        let (x_P_left, x_P, x_P2) = cs.allocate_multiplier(P_i.map(|P_i| {
            (
                P_i.x().unwrap().into_scalar(),
                P_i.x().unwrap().into_scalar(),
            )
        }))?;
        let (y_P_left, y_P, y_P2) = cs.allocate_multiplier(P_i.map(|P_i| {
            (
                P_i.y().unwrap().into_scalar(),
                P_i.y().unwrap().into_scalar(),
            )
        }))?;
        // `allocate_multiplier` only enforces left * right = out, so tie left to right:
        // otherwise x_P2 and y_P2 are free and the curve equation below holds for any point
        cs.constrain(x_P_left - x_P);
        cs.constrain(y_P_left - y_P);
        let (_, _, x_P3) = cs.multiply(x_P2.into(), x_P.into());
        let (P_i_1_x, P_i_1_y) = *P_vars.last().unwrap();
        P_vars.push((x_P, y_P));

        // check curve equation for current points
        //debug!("{:?} = {:?}", P_i.map(|P_i| P_i.x().unwrap().into_scalar() * P_i.x().unwrap().into_scalar() * P_i.x().unwrap().into_scalar() + w_a * P_i.x().unwrap().into_scalar() + w_b), P_i.map(| P_i| P_i.y().unwrap().into_scalar()));
        let curve_eq = y_P2 - x_P3 - x_P * w_a - w_b;
        cs.constrain(curve_eq);

        // check that Δ_i, -P_i, P_i_1 is on the same line
        let (_, _, t1) = cs.multiply(P_i_1_y + y_P, Δ_i_x.clone() - x_P);
        let (_, _, t2) = cs.multiply(Δ_i_y + y_P, P_i_1_x - x_P);
        cs.constrain(t1 - t2);

        // On-curve and co-linear also hold for P_i = -P_i_1 and P_i = -Δ_i, whatever the
        // witness. Exclude them, so that -P_i is the third point of the line and
        // P_i = P_i_1 + Δ_i.
        nonzero_lc_gadget(cs, P_i_1_x - x_P)?;
        nonzero_lc_gadget(cs, Δ_i_x - x_P)?;
    }
    trace!(
        "P_final = {:?}",
        P.as_ref().map(|P| P.iter().last().clone())
    );

    let (x_var, y_var) = *P_vars.last().unwrap();
    let P = P.as_ref().map(|P| P.iter().last().unwrap().clone());

    Ok(AllocatedPoint {
        x: AllocatedScalar {
            variable: x_var,
            assignment: P.map(|P| P.x().unwrap().into_scalar()),
        },
        y: AllocatedScalar {
            variable: y_var,
            assignment: P.map(|P| P.y().unwrap().into_scalar()),
        },
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Witness {
    P_i: CortadoAffine,
    Δ_i: CortadoAffine,
    P_i_1: CortadoAffine,
    s_i: Scalar,
}

/// second ver. of gadget for scalar multiplication, returns constrainted variable R = λ_a * Q_b
/// based on https://eprint.iacr.org/archive/2024/397/20250504:183956
fn scalar_mul_bits_v2<CS: ConstraintSystem>(
    cs: &mut CS,
    k: &ScalarBits,
    Q_b: CortadoAffine,
) -> Result<AllocatedPoint, R1CSError> {
    let λ_a = k.assignment;
    let l = (MODULUS_BIT_SIZE) as i32;
    let Δ1 = S.get_or_init(|| {
        let G = CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y);
        (0..l)
            .map(|i| {
                if i == (l - 1) {
                    (G * cortado::Fr::from(-(l * l + l - 2) / 2)).into_affine()
                } else {
                    (G * cortado::Fr::from(i + 2)).into_affine()
                }
            })
            .collect()
    });

    let mut δ = vec![Q_b];
    for _ in 1..l as usize {
        δ.push(((*δ.last().unwrap()) * cortado::Fr::from(2)).into_affine());
    }
    let Δ2: Vec<_> = Δ1
        .iter()
        .zip(δ.iter())
        .map(|(x, y)| (*x + y).into_affine())
        .collect();
    finite_table(&Q_b, &Δ2)?;
    let k_vars = &k.vars;

    // P_0 = Δ_0
    let (_, _, x0) = cs.multiply(
        Variable::One() * Δ1[0].x().unwrap().into_scalar()
            + k_vars[0] * (Δ2[0].x().unwrap() - Δ1[0].x().unwrap()).into_scalar(),
        Variable::One().into(),
    ); // x0 = k[0]*(x-x')+x'
    let (_, _, y0) = cs.multiply(
        Variable::One() * Δ1[0].y().unwrap().into_scalar()
            + k_vars[0] * (Δ2[0].y().unwrap() - Δ1[0].y().unwrap()).into_scalar(),
        Variable::One().into(),
    ); // y0 = k[0]*(y-y')+y'
    let mut P_vars = vec![(x0, y0)];

    let mut P = λ_a
        .map(|λ_a| vec![(Q_b * cortado::Fr::from(λ_a.get_bit(0) as u64) + Δ1[0]).into_affine()]);

    for i in 1..l as usize {
        // calculate witness P_i = P_i_1 + Δ_i
        let w = λ_a.map(|λ_a| {
            let P_i_1 = *(P.as_ref().unwrap().last().unwrap());
            let P_i = (P_i_1
                + match λ_a.get_bit(i) {
                    true => Δ2[i],
                    false => Δ1[i],
                })
            .into_affine();
            let Δ_i = if λ_a.get_bit(i) { Δ2[i] } else { Δ1[i] };
            P.as_mut().unwrap().push(P_i);
            let s_i = (P_i_1.y().unwrap().into_scalar() - Δ_i.y().unwrap().into_scalar())
                * (P_i_1.x().unwrap().into_scalar() - Δ_i.x().unwrap().into_scalar()).invert();

            Witness {
                P_i_1,
                P_i,
                Δ_i,
                s_i,
            }
        });

        let (Δ_i_x, Δ_i_y) = (
            Variable::One() * Δ1[i].x().unwrap().into_scalar()
                + k_vars[i] * (Δ2[i].x().unwrap() - Δ1[i].x().unwrap()).into_scalar(),
            Variable::One() * Δ1[i].y().unwrap().into_scalar()
                + k_vars[i] * (Δ2[i].y().unwrap() - Δ1[i].y().unwrap()).into_scalar(),
        );

        let (s_i_left, s_i, s_i_2) = cs.allocate_multiplier(w.as_ref().map(|w| (w.s_i, w.s_i)))?;
        // `allocate_multiplier` only enforces left * right = out, so tie left to right:
        // otherwise s_i_2 is free, x_P is unconstrained and the result can be any point
        cs.constrain(s_i_left - s_i);
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
    trace!(
        "P_final = {:?}",
        P.as_ref().map(|P| P.iter().last().clone())
    );
    let (x_var, y_var) = *P_vars.last().unwrap();
    let P = P.as_ref().map(|P| P.iter().last().unwrap().clone());

    Ok(AllocatedPoint {
        x: AllocatedScalar {
            variable: x_var,
            assignment: P.map(|P| P.x().unwrap().into_scalar()),
        },
        y: AllocatedScalar {
            variable: y_var,
            assignment: P.map(|P| P.y().unwrap().into_scalar()),
        },
    })
}

/// gadget computing R <- x * Q, there exists two versions of this gadget: the first check curve equation and points co-linearity
/// while the second check co-linearity along with the square of the line slope (this one takes ~760 less multipliers)
///
/// Both versions add points with incomplete formulas, which are sound only while the running
/// sum P_{i-1} never equals Δ_i. With Q's discrete log known (a member knows the secrets of
/// its own nodes, and Q = G for public keys), that equality needs the discrete log of the
/// alternative generator H with respect to G. The offsets [c_i]H are therefore only as good as
/// the evidence that nobody knows it.
pub fn scalar_mul_gadget<CS: ConstraintSystem>(
    ver: u8,
    cs: &mut CS,
    x: AllocatedScalar,
    Q: CortadoAffine,
) -> Result<AllocatedPoint, R1CSError> {
    let k = scalar_bits_gadget(cs, x)?;
    scalar_mul_bits_gadget(ver, cs, &k, Q)
}

/// `scalar_mul_gadget` for a scalar whose bits are already decomposed (`scalar_bits_gadget`).
pub fn scalar_mul_bits_gadget<CS: ConstraintSystem>(
    ver: u8,
    cs: &mut CS,
    k: &ScalarBits,
    Q: CortadoAffine,
) -> Result<AllocatedPoint, R1CSError> {
    match ver {
        1 => scalar_mul_bits_v1(cs, k, Q),
        2 => scalar_mul_bits_v2(cs, k, Q),
        _ => Err(R1CSError::GadgetError {
            description: "invalid scalar mul gadget version".into(),
        }),
    }
}

/// gadget constraining λ_ab = x(λ_a * Q_b), there exists two versions of this gadget as in `scalar_mul_gadget`
pub fn dh_gadget<CS: ConstraintSystem>(
    ver: u8,
    cs: &mut CS,
    λ_a: AllocatedScalar,
    λ_ab: AllocatedScalar,
    Q_b: CortadoAffine,
) -> Result<(), R1CSError> {
    let var_R = scalar_mul_gadget(ver, cs, λ_a, Q_b)?;
    cs.constrain(var_R.x.variable - λ_ab.variable);
    Ok(())
}

/// gadget constraining λ_ab = x(λ_a * Q_b) & Q_ab = [λ_ab]P, and at level 0 also Q_a = [λ_a]P
///
/// At level 0 both scalar multiplications by λ_a walk one decomposition of it: besides saving
/// 381 multipliers, which keeps a level-0 proof within 4096, it makes the leaf key and the DH use
/// the same integer by construction.
pub fn art_level_gadget<CS: ConstraintSystem>(
    ver: u8,
    cs: &mut CS,
    level: usize,
    λ_a: AllocatedScalar,
    λ_ab: AllocatedScalar,
    Q_a: CortadoAffine,
    Q_ab: CortadoAffine,
    Q_b: CortadoAffine,
) -> Result<(), R1CSError> {
    // the public keys come from the received change: a key at infinity is an error, not a panic
    let (Q_a_x, Q_a_y) = affine_coordinates(&Q_a)?;
    let (Q_ab_x, Q_ab_y) = affine_coordinates(&Q_ab)?;

    let k_a = scalar_bits_gadget(cs, λ_a)?;
    if level == 0 {
        // constrain Q_a = [λ_a]P
        let var_Q = scalar_mul_bits_gadget(ver, cs, &k_a, CortadoAffine::generator())?;
        cs.constrain(var_Q.x.variable - Q_a_x);
        cs.constrain(var_Q.y.variable - Q_a_y);
    }

    // constrain λ_ab = x(λ_a * Q_b)
    let var_R = scalar_mul_bits_gadget(ver, cs, &k_a, Q_b)?;
    cs.constrain(var_R.x.variable - λ_ab.variable);

    // constrain Q_ab = [λ_ab]P
    let var_Q = scalar_mul_gadget(ver, cs, λ_ab, CortadoAffine::generator())?;
    cs.constrain(var_Q.x.variable - Q_ab_x);
    cs.constrain(var_Q.y.variable - Q_ab_y);

    Ok(())
}

/// The affine coordinates of `P` as scalars, or an error when `P` is the point at infinity.
pub(crate) fn affine_coordinates(P: &CortadoAffine) -> Result<(Scalar, Scalar), R1CSError> {
    match (P.x(), P.y()) {
        (Some(x), Some(y)) => Ok((x.into_scalar(), y.into_scalar())),
        _ => Err(R1CSError::GadgetError {
            description: "point at infinity".into(),
        }),
    }
}

/// Rejects a base point `Q` at infinity, and tables in which some Δ2_i = Δ1_i + [2^i]Q is at
/// infinity. Δ1_i = [c_i]H, so anyone can make Δ2_i infinite with Q = -[c_i / 2^i]H, without
/// knowing any discrete log; such a Q can reach the verifier as a co-path key of a crafted tree.
fn finite_table(Q: &CortadoAffine, Δ2: &[CortadoAffine]) -> Result<(), R1CSError> {
    if Q.is_zero() || Δ2.iter().any(|p| p.is_zero()) {
        return Err(R1CSError::GadgetError {
            description: "scalar multiplication base or table point at infinity".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    fn dh_gadget_prove(
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
        let λ_a = AllocatedScalar::new(var_a, Some(λ_a));
        let λ_ab = AllocatedScalar::new(var_ab, Some(λ_ab));
        let mut start = Instant::now();

        dh_gadget(ver, &mut prover, λ_a, λ_ab, Q_b)?;

        debug!(
            "DHGadget prover synthetize time: {:?}, metrics: {:?}",
            start.elapsed(),
            prover.metrics()
        );
        start = Instant::now();
        let proof = prover.prove(bp_gens)?;
        debug!(
            "DHGadget proving time: {:?}, proof_size = {:?}",
            start.elapsed(),
            proof.to_bytes().len()
        );

        Ok((proof, (a_commitment, ab_commitment)))
    }

    fn dh_gadget_verify(
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
        let λ_a = AllocatedScalar::new(var_a, None);
        let λ_ab = AllocatedScalar::new(var_ab, None);
        let mut start = Instant::now();

        dh_gadget(ver, &mut verifier, λ_a, λ_ab, Q_b)?;

        debug!("DHGadget verifier synthetize time: {:?}", start.elapsed());
        start = Instant::now();
        let r = verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(|_| R1CSError::VerificationError);
        debug!("DHGadget verification time: {:?}", start.elapsed());
        r
    }

    fn art_level_prove(
        ver: u8,
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        level: usize,
        Q_a: CortadoAffine,
        Q_b: CortadoAffine,
        Q_ab: CortadoAffine,
        λ_a: Scalar,
        λ_ab: Scalar,
    ) -> Result<(R1CSProof, (CompressedRistretto, CompressedRistretto)), R1CSError> {
        let mut blinding_rng = thread_rng();

        let mut transcript = Transcript::new(b"ARTLevel");

        // 1. Create a prover
        let mut prover = Prover::new(pc_gens, &mut transcript);

        // 2. Commit high-level variables
        let (a_commitment, var_a) = prover.commit(λ_a, Scalar::random(&mut blinding_rng));
        let (ab_commitment, var_ab) = prover.commit(λ_ab, Scalar::random(&mut blinding_rng));

        let λ_a = AllocatedScalar::new(var_a, Some(λ_a));
        let λ_ab = AllocatedScalar::new(var_ab, Some(λ_ab));
        let mut start = Instant::now();

        art_level_gadget(ver, &mut prover, level, λ_a, λ_ab, Q_a, Q_ab, Q_b)?;

        debug!(
            "ARTLevel prover synthetize time: {:?}, metrics: {:?}",
            start.elapsed(),
            prover.metrics()
        );
        start = Instant::now();

        let proof = prover.prove(bp_gens)?;

        debug!(
            "ARTLevel proving time: {:?}, proof_size = {:?}",
            start.elapsed(),
            proof.to_bytes().len()
        );

        Ok((proof, (a_commitment, ab_commitment)))
    }

    fn art_level_verify(
        ver: u8,
        pc_gens: &PedersenGens,
        bp_gens: &BulletproofGens,
        proof: R1CSProof,
        level: usize,
        Q_a: CortadoAffine,
        Q_b: CortadoAffine,
        Q_ab: CortadoAffine,
        a_commitment: CompressedRistretto,
        ab_commitment: CompressedRistretto,
    ) -> Result<(), R1CSError> {
        let mut transcript = Transcript::new(b"ARTLevel");
        let mut verifier = Verifier::new(&mut transcript);

        let var_a = verifier.commit(a_commitment);
        let var_ab = verifier.commit(ab_commitment);

        let λ_a = AllocatedScalar::new(var_a, None);
        let λ_ab = AllocatedScalar::new(var_ab, None);
        let mut start = Instant::now();

        art_level_gadget(ver, &mut verifier, level, λ_a, λ_ab, Q_a, Q_ab, Q_b)?;

        debug!("ARTLevel verifier synthetize time: {:?}", start.elapsed());
        start = Instant::now();

        let r = verifier
            .verify(&proof, &pc_gens, &bp_gens)
            .map_err(|_| R1CSError::VerificationError);

        debug!("ARTLevel verification time: {:?}", start.elapsed());

        r
    }

    fn dh_gadget_roundtrip(ver: u8) -> Result<(), R1CSError> {
        let mut blinding_rng = rand::thread_rng();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(4096, 1);

        let r: cortado::Fr = blinding_rng.r#gen();
        let Q_b = (CortadoAffine::generator() * r).into_affine();
        let λ_a: cortado::Fr = blinding_rng.r#gen();

        let R = (Q_b * λ_a).into_affine();
        debug!("R_real={:?}", R);

        let (proof, (var_a, var_b)) = dh_gadget_prove(
            ver,
            &pc_gens,
            &bp_gens,
            Q_b,
            Scalar::from_bytes_mod_order(
                (&λ_a.into_bigint().to_bytes_le()[..]).try_into().unwrap(),
            ),
            R.x().unwrap().into_scalar(),
        )?;

        dh_gadget_verify(ver, &pc_gens, &bp_gens, proof, Q_b, var_a, var_b)
    }

    fn art_level_gadget_roundtrip(ver: u8) -> Result<(), R1CSError> {
        let mut blinding_rng = rand::thread_rng();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(8192, 1);

        let r: cortado::Fr = blinding_rng.r#gen();
        let Q_b = (CortadoAffine::generator() * r).into_affine();
        let λ_a: cortado::Fr = blinding_rng.r#gen();
        let Q_a = (CortadoAffine::generator() * λ_a).into_affine();
        let λ_ab = cortado::Fr::from_le_bytes_mod_order(
            &(Q_b * λ_a)
                .into_affine()
                .x()
                .unwrap()
                .into_bigint()
                .to_bytes_le(),
        );
        let Q_ab = (CortadoAffine::generator() * λ_ab).into_affine();
        let R = (Q_b * λ_a).into_affine();
        debug!("Q_ab_real={:?}", Q_ab);

        let (proof, (var_a, var_b)) = art_level_prove(
            ver,
            &pc_gens,
            &bp_gens,
            1,
            Q_a,
            Q_b,
            Q_ab,
            Scalar::from_bytes_mod_order(
                (&λ_a.into_bigint().to_bytes_le()[..]).try_into().unwrap(),
            ),
            R.x().unwrap().into_scalar(),
        )?;

        art_level_verify(
            ver, &pc_gens, &bp_gens, proof, 1, Q_a, Q_b, Q_ab, var_a, var_b,
        )
    }

    #[test]
    fn dh_gadget_roundtrip_v1() {
        assert!(dh_gadget_roundtrip(1).is_ok());
    }

    #[test]
    fn dh_gadget_roundtrip_v2() {
        assert!(dh_gadget_roundtrip(2).is_ok());
    }

    #[test]
    fn art_level_gadget_roundtrip_v1() {
        assert!(art_level_gadget_roundtrip(1).is_ok());
    }

    #[test]
    fn art_level_gadget_roundtrip_v2() {
        assert!(art_level_gadget_roundtrip(2).is_ok());
    }
}

/// Soundness of the scalar multiplication gadgets: a prover that emits exactly the
/// constraints of a gadget, but assigns a forged witness, must not convince the verifier.
///
/// The mirrors below copy the gadgets' constraints. `mirror_v*_matches_gadget` checks that a
/// mirror still emits the same constraints as its gadget (an honest witness verifies against
/// the gadget); update the mirror together with the gadget.
#[cfg(test)]
mod soundness_tests {
    use super::*;

    /// How a mirrored prover assigns the walk P_0, ..., P_{l-1}.
    #[derive(Clone, Copy)]
    enum Witness {
        /// The honest walk P_i = P_{i-1} + Δ_i.
        Honest,
        /// Ends the walk at the given point by assigning the left wires of the multipliers
        /// freely (v1: only the x-coordinate is reached).
        FreeWires(Scalar, Scalar),
        /// v1 only: ends the walk at -Δ_{l-1}, which is on the curve and on the line.
        MinusDelta,
        /// The honest walk for the bits of λ_a + ℓ, which has the same value modulo ℓ.
        Aliased,
    }

    struct WalkStart {
        d1: Vec<CortadoAffine>,
        d2: Vec<CortadoAffine>,
        k_vars: Vec<Variable>,
        p0_vars: (Variable, Variable),
        p0: CortadoAffine,
    }

    fn xy(p: &CortadoAffine) -> (Scalar, Scalar) {
        (p.x().unwrap().into_scalar(), p.y().unwrap().into_scalar())
    }

    fn fr_to_scalar(x: &cortado::Fr) -> Scalar {
        Scalar::from_bytes_mod_order((&x.into_bigint().to_bytes_le()[..]).try_into().unwrap())
    }

    /// The integer whose bits a mirrored prover assigns to the committed scalar `a`.
    fn bits_of(a: Scalar, witness: Witness) -> BigInt<4> {
        let mut k = cortado::Fq::from_le_bytes_mod_order(&a.to_bytes()).into_bigint();
        if let Witness::Aliased = witness {
            k.add_with_carry(&cortado::Fq::MODULUS);
        }
        k
    }

    /// The constraints of `bin_equality_gadget(cs, var_a, _, MODULUS_BIT_SIZE)`, assigning the
    /// bits of `k`.
    fn decompose<CS: ConstraintSystem>(
        cs: &mut CS,
        var_a: Variable,
        k: &BigInt<4>,
    ) -> Result<Vec<Variable>, R1CSError> {
        let bits: Vec<Variable> = (0..MODULUS_BIT_SIZE as usize)
            .map(|i| {
                let bit = k.get_bit(i) as u64;
                let (p, q, o) = cs.allocate_multiplier(Some(((1 - bit).into(), bit.into())))?;
                cs.constrain(o.into());
                cs.constrain(p + (q - Scalar::from(1u64)));
                Ok(q)
            })
            .collect::<Result<_, R1CSError>>()?;
        let x_acc: LinearCombination = acc(&bits, Scalar::from(2u64));
        cs.constrain(LinearCombination::from(var_a) - x_acc);
        Ok(bits)
    }

    /// The constraints of `scalar_bits_gadget` for `var_a`, assigning the bits of `k`.
    fn mirror_bits<CS: ConstraintSystem>(
        cs: &mut CS,
        var_a: Variable,
        k: &BigInt<4>,
    ) -> Result<Vec<Variable>, R1CSError> {
        let k_vars = decompose(cs, var_a, k)?;
        canonical_bits_gadget(cs, &k_vars)?;
        Ok(k_vars)
    }

    /// The tables and P_0 for the bits `k_vars` (assigned the bits of `k`), as both gadgets build
    /// them.
    fn walk_start<CS: ConstraintSystem>(
        cs: &mut CS,
        k_vars: &[Variable],
        k: &BigInt<4>,
        Q_b: CortadoAffine,
    ) -> Result<WalkStart, R1CSError> {
        let l = MODULUS_BIT_SIZE as i32;
        let d1 = S
            .get_or_init(|| {
                let G = CortadoAffine::new_unchecked(
                    cortado::ALT_GENERATOR_X,
                    cortado::ALT_GENERATOR_Y,
                );
                (0..l)
                    .map(|i| {
                        if i == (l - 1) {
                            (G * cortado::Fr::from(-(l * l + l - 2) / 2)).into_affine()
                        } else {
                            (G * cortado::Fr::from(i + 2)).into_affine()
                        }
                    })
                    .collect()
            })
            .clone();
        let mut δ = vec![Q_b];
        for _ in 1..l as usize {
            δ.push(((*δ.last().unwrap()) * cortado::Fr::from(2)).into_affine());
        }
        let d2: Vec<CortadoAffine> = d1
            .iter()
            .zip(δ.iter())
            .map(|(x, y)| (*x + y).into_affine())
            .collect();
        let k_vars = k_vars.to_vec();
        let (_, _, x0) = cs.multiply(
            Variable::One() * d1[0].x().unwrap().into_scalar()
                + k_vars[0] * (d2[0].x().unwrap() - d1[0].x().unwrap()).into_scalar(),
            Variable::One().into(),
        );
        let (_, _, y0) = cs.multiply(
            Variable::One() * d1[0].y().unwrap().into_scalar()
                + k_vars[0] * (d2[0].y().unwrap() - d1[0].y().unwrap()).into_scalar(),
            Variable::One().into(),
        );
        let p0 = (Q_b * cortado::Fr::from(k.get_bit(0) as u64) + d1[0]).into_affine();

        Ok(WalkStart {
            d1,
            d2,
            k_vars,
            p0_vars: (x0, y0),
            p0,
        })
    }

    /// The linear combinations of Δ_i, as both gadgets build them.
    fn delta_lc(st: &WalkStart, i: usize) -> (LinearCombination, LinearCombination) {
        (
            Variable::One() * st.d1[i].x().unwrap().into_scalar()
                + st.k_vars[i] * (st.d2[i].x().unwrap() - st.d1[i].x().unwrap()).into_scalar(),
            Variable::One() * st.d1[i].y().unwrap().into_scalar()
                + st.k_vars[i] * (st.d2[i].y().unwrap() - st.d1[i].y().unwrap()).into_scalar(),
        )
    }

    /// The constraints of `scalar_mul_gadget(1 or 2, ..)` (decomposition, then walk), with
    /// `witness`.
    fn mirror_v1<CS: ConstraintSystem>(
        cs: &mut CS,
        λ_a: AllocatedScalar,
        Q_b: CortadoAffine,
        witness: Witness,
    ) -> Result<AllocatedPoint, R1CSError> {
        let k = bits_of(λ_a.assignment.unwrap(), witness);
        let k_vars = mirror_bits(cs, λ_a.variable, &k)?;
        mirror_walk_v1(cs, &k_vars, &k, Q_b, witness)
    }

    /// The constraints of `scalar_mul_bits_v1` for the bits `k_vars` of `k`, with `witness`.
    fn mirror_walk_v1<CS: ConstraintSystem>(
        cs: &mut CS,
        k_vars: &[Variable],
        k: &BigInt<4>,
        Q_b: CortadoAffine,
        witness: Witness,
    ) -> Result<AllocatedPoint, R1CSError> {
        let (w_a, w_b) = (
            cortado::Parameters::COEFF_A.into_scalar(),
            cortado::Parameters::COEFF_B.into_scalar(),
        );
        let st = walk_start(cs, k_vars, k, Q_b)?;
        let l = MODULUS_BIT_SIZE as usize;
        let sel = |i: usize| if k.get_bit(i) { st.d2[i] } else { st.d1[i] };
        let mut P_vars = vec![st.p0_vars];
        let mut cur_aff = st.p0;
        let mut cur = xy(&st.p0);

        for i in 1..l {
            let (dx, dy) = xy(&sel(i));
            let (px, py) = cur;
            let last = i == l - 1;
            // (x, y, left wire of x^2, left wire of y^2); the honest left wires are x and y
            let (x, y, x_left, y_left) = match witness {
                Witness::FreeWires(X, _) if last => {
                    // y on the line through P_{i-1} and Δ_i reflected; the left wire of y^2
                    // absorbs the curve equation
                    let y = (dy * (px - X) - py * (dx - X)) * (dx - px).invert();
                    (X, y, X, (X * X * X + w_a * X + w_b) * y.invert())
                }
                Witness::MinusDelta if last => (dx, -dy, dx, -dy),
                _ => {
                    cur_aff = (cur_aff + sel(i)).into_affine();
                    let (x, y) = xy(&cur_aff);
                    (x, y, x, y)
                }
            };

            let (x_left_var, x_P, x_P2) = cs.allocate_multiplier(Some((x_left, x)))?;
            let (y_left_var, y_P, y_P2) = cs.allocate_multiplier(Some((y_left, y)))?;
            cs.constrain(x_left_var - x_P);
            cs.constrain(y_left_var - y_P);
            let (_, _, x_P3) = cs.multiply(x_P2.into(), x_P.into());
            let (P_i_1_x, P_i_1_y) = *P_vars.last().unwrap();
            P_vars.push((x_P, y_P));
            cs.constrain(y_P2 - x_P3 - x_P * w_a - w_b);
            let (d_x, d_y) = delta_lc(&st, i);
            let (_, _, t1) = cs.multiply(P_i_1_y + y_P, d_x.clone() - x_P);
            let (_, _, t2) = cs.multiply(d_y + y_P, P_i_1_x - x_P);
            cs.constrain(t1 - t2);
            nonzero_lc_gadget(cs, P_i_1_x - x_P)?;
            nonzero_lc_gadget(cs, d_x - x_P)?;
            cur = (x, y);
        }

        let (x_var, y_var) = *P_vars.last().unwrap();
        Ok(AllocatedPoint {
            x: AllocatedScalar::new(x_var, Some(cur.0)),
            y: AllocatedScalar::new(y_var, Some(cur.1)),
        })
    }

    /// The constraints of `scalar_mul_gadget(1 or 2, ..)` (decomposition, then walk), with
    /// `witness`.
    fn mirror_v2<CS: ConstraintSystem>(
        cs: &mut CS,
        λ_a: AllocatedScalar,
        Q_b: CortadoAffine,
        witness: Witness,
    ) -> Result<AllocatedPoint, R1CSError> {
        let k = bits_of(λ_a.assignment.unwrap(), witness);
        let k_vars = mirror_bits(cs, λ_a.variable, &k)?;
        mirror_walk_v2(cs, &k_vars, &k, Q_b, witness)
    }

    /// The constraints of `scalar_mul_bits_v2` for the bits `k_vars` of `k`, with `witness`.
    fn mirror_walk_v2<CS: ConstraintSystem>(
        cs: &mut CS,
        k_vars: &[Variable],
        k: &BigInt<4>,
        Q_b: CortadoAffine,
        witness: Witness,
    ) -> Result<AllocatedPoint, R1CSError> {
        let st = walk_start(cs, k_vars, k, Q_b)?;
        let l = MODULUS_BIT_SIZE as usize;
        let sel = |i: usize| if k.get_bit(i) { st.d2[i] } else { st.d1[i] };
        let mut P_vars = vec![st.p0_vars];
        let mut cur_aff = st.p0;
        let mut cur = xy(&st.p0);

        for i in 1..l {
            let (dx, dy) = xy(&sel(i));
            let (px, py) = cur;
            // fixed by s * (x_{i-1} - x_Δ) = y_{i-1} - y_Δ
            let s = (py - dy) * (px - dx).invert();
            let (x, y) = match witness {
                Witness::FreeWires(X, Y) if i == l - 2 => {
                    // x' such that the line of the last step passes through (X, Y); with
                    // y' = c0 - s * x' the condition is linear in x'
                    let (ex, ey) = xy(&sel(l - 1));
                    let c0 = s * px - py;
                    let x1 = ((c0 - ey) * X - c0 * ex - Y * ex) * (s * (X - ex) - ey - Y).invert();
                    (x1, c0 - s * x1)
                }
                Witness::FreeWires(X, _) if i == l - 1 => (X, s * (px - X) - py),
                _ => {
                    cur_aff = (cur_aff + sel(i)).into_affine();
                    xy(&cur_aff)
                }
            };
            // the honest left wire is s; this one makes left * s = x + x_{i-1} + x_Δ
            let left = (x + px + dx) * s.invert();

            let (s_left, s_var, s2) = cs.allocate_multiplier(Some((left, s)))?;
            cs.constrain(s_left - s_var);
            let x_P = cs.allocate(Some(x))?;
            let y_P = cs.allocate(Some(y))?;
            let (P_i_1_x, P_i_1_y) = *P_vars.last().unwrap();
            P_vars.push((x_P, y_P));
            let (d_x, d_y) = delta_lc(&st, i);
            cs.constrain(s2 - x_P - P_i_1_x - d_x.clone());
            let (_, _, t1) = cs.multiply(Scalar::ONE * s_var, P_i_1_x - d_x);
            cs.constrain(t1 - (P_i_1_y - d_y));
            let (_, _, t2) = cs.multiply(Scalar::ONE * s_var, P_i_1_x - x_P);
            cs.constrain(t2 - (P_i_1_y + y_P));
            cur = (x, y);
        }

        let (x_var, y_var) = *P_vars.last().unwrap();
        Ok(AllocatedPoint {
            x: AllocatedScalar::new(x_var, Some(cur.0)),
            y: AllocatedScalar::new(y_var, Some(cur.1)),
        })
    }

    fn mirror<CS: ConstraintSystem>(
        ver: u8,
        cs: &mut CS,
        λ_a: AllocatedScalar,
        Q_b: CortadoAffine,
        witness: Witness,
    ) -> Result<AllocatedPoint, R1CSError> {
        match ver {
            1 => mirror_v1(cs, λ_a, Q_b, witness),
            _ => mirror_v2(cs, λ_a, Q_b, witness),
        }
    }

    /// Proves λ_ab = x([λ_a]Q_b) with the mirrored prover and `witness`, and returns whether
    /// `dh_gadget` accepts the proof.
    fn dh_verifies(ver: u8, witness: Witness) -> bool {
        let mut rng = rand::thread_rng();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(4096, 1);
        let r: cortado::Fr = rng.r#gen();
        let Q_b = (CortadoAffine::generator() * r).into_affine();
        let λ_a = fr_to_scalar(&rng.r#gen::<cortado::Fr>());

        // the x-coordinate the walk ends at, from a dry run
        let mut dry_transcript = Transcript::new(b"dry run");
        let mut dry = Prover::new(&pc_gens, &mut dry_transcript);
        let (_, dry_a) = dry.commit(λ_a, Scalar::ONE);
        let λ_ab = mirror(
            ver,
            &mut dry,
            AllocatedScalar::new(dry_a, Some(λ_a)),
            Q_b,
            witness,
        )
        .unwrap()
        .x
        .assignment
        .unwrap();

        let mut prover_transcript = Transcript::new(b"DHGadget");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let (a_commitment, var_a) = prover.commit(λ_a, Scalar::random(&mut rng));
        let (ab_commitment, var_ab) = prover.commit(λ_ab, Scalar::random(&mut rng));
        let R = mirror(
            ver,
            &mut prover,
            AllocatedScalar::new(var_a, Some(λ_a)),
            Q_b,
            witness,
        )
        .unwrap();
        prover.constrain(R.x.variable - var_ab);
        let Ok(proof) = prover.prove(&bp_gens) else {
            return false;
        };

        let mut verifier_transcript = Transcript::new(b"DHGadget");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let var_a = verifier.commit(a_commitment);
        let var_ab = verifier.commit(ab_commitment);
        dh_gadget(
            ver,
            &mut verifier,
            AllocatedScalar::new(var_a, None),
            AllocatedScalar::new(var_ab, None),
            Q_b,
        )
        .unwrap();
        verifier.verify(&proof, &pc_gens, &bp_gens).is_ok()
    }

    #[test]
    fn mirror_v1_matches_gadget() {
        assert!(dh_verifies(1, Witness::Honest));
    }

    #[test]
    fn mirror_v2_matches_gadget() {
        assert!(dh_verifies(2, Witness::Honest));
    }

    #[test]
    fn v1_rejects_free_square_wires() {
        let target = (Scalar::from(42u64), Scalar::from(7u64));
        assert!(!dh_verifies(1, Witness::FreeWires(target.0, target.1)));
    }

    #[test]
    fn v1_rejects_walk_ending_at_minus_delta() {
        assert!(!dh_verifies(1, Witness::MinusDelta));
    }

    #[test]
    fn v2_rejects_free_slope_square() {
        let target = (Scalar::from(42u64), Scalar::from(7u64));
        assert!(!dh_verifies(2, Witness::FreeWires(target.0, target.1)));
    }

    #[test]
    fn v1_rejects_aliased_bits() {
        assert!(!dh_verifies(1, Witness::Aliased));
    }

    #[test]
    fn v2_rejects_aliased_bits() {
        assert!(!dh_verifies(2, Witness::Aliased));
    }

    /// Proves the constraints of `art_level_gadget(2, _, 0, ...)` with the mirrored v2 prover and
    /// returns whether the gadget accepts the proof. Like the gadget, the prover decomposes λ_a
    /// once (assigning the bits for `a_bits`) and walks those bits for the leaf key and for the
    /// DH, then decomposes and walks λ_ab for the parent key; `walks` is the witness of each walk.
    ///
    /// The generators hold 4096 multipliers: the honest proof fitting them is part of what
    /// `level0_mirror_matches_gadget` checks.
    fn level0_verifies(
        λ_a: Scalar,
        λ_ab: Scalar,
        Q_a: CortadoAffine,
        Q_ab: CortadoAffine,
        Q_b: CortadoAffine,
        a_bits: Witness,
        walks: [Witness; 3],
    ) -> bool {
        let mut rng = rand::thread_rng();
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(4096, 1);
        let G = CortadoAffine::generator();
        let (qa_x, qa_y) = xy(&Q_a);
        let (qab_x, qab_y) = xy(&Q_ab);

        let mut prover_transcript = Transcript::new(b"ARTLevel");
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
        let (a_commitment, var_a) = prover.commit(λ_a, Scalar::random(&mut rng));
        let (ab_commitment, var_ab) = prover.commit(λ_ab, Scalar::random(&mut rng));
        let ab = AllocatedScalar::new(var_ab, Some(λ_ab));
        let k_a = bits_of(λ_a, a_bits);
        let a_vars = mirror_bits(&mut prover, var_a, &k_a).unwrap();
        let q = mirror_walk_v2(&mut prover, &a_vars, &k_a, G, walks[0]).unwrap();
        prover.constrain(q.x.variable - qa_x);
        prover.constrain(q.y.variable - qa_y);
        let R = mirror_walk_v2(&mut prover, &a_vars, &k_a, Q_b, walks[1]).unwrap();
        prover.constrain(R.x.variable - var_ab);
        let q_ab = mirror_v2(&mut prover, ab, G, walks[2]).unwrap();
        prover.constrain(q_ab.x.variable - qab_x);
        prover.constrain(q_ab.y.variable - qab_y);
        let Ok(proof) = prover.prove(&bp_gens) else {
            return false;
        };

        let mut verifier_transcript = Transcript::new(b"ARTLevel");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let var_a = verifier.commit(a_commitment);
        let var_ab = verifier.commit(ab_commitment);
        art_level_gadget(
            2,
            &mut verifier,
            0,
            AllocatedScalar::new(var_a, None),
            AllocatedScalar::new(var_ab, None),
            Q_a,
            Q_ab,
            Q_b,
        )
        .unwrap();
        verifier.verify(&proof, &pc_gens, &bp_gens).is_ok()
    }

    fn scalar_to_fr(x: &Scalar) -> cortado::Fr {
        cortado::Fr::from_le_bytes_mod_order(&x.to_bytes())
    }

    #[test]
    fn level0_mirror_matches_gadget() {
        let mut rng = rand::thread_rng();
        let G = CortadoAffine::generator();
        let Q_b = (G * rng.r#gen::<cortado::Fr>()).into_affine();
        let λ_a = Scalar::random(&mut rng);
        let Q_a = (G * scalar_to_fr(&λ_a)).into_affine();
        let λ_ab = xy(&(Q_b * scalar_to_fr(&λ_a)).into_affine()).0;
        let Q_ab = (G * scalar_to_fr(&λ_ab)).into_affine();
        assert!(level0_verifies(
            λ_a,
            λ_ab,
            Q_a,
            Q_ab,
            Q_b,
            Witness::Honest,
            [Witness::Honest; 3]
        ));
    }

    /// A level-0 proof for a leaf key whose secret the prover does not know, with a node secret
    /// of the prover's choice.
    #[test]
    fn v2_rejects_level_proof_for_foreign_leaf_key() {
        let mut rng = rand::thread_rng();
        let G = CortadoAffine::generator();
        let Q_a = (G * rng.r#gen::<cortado::Fr>()).into_affine();
        let Q_b = (G * rng.r#gen::<cortado::Fr>()).into_affine();
        let guess = fr_to_scalar(&rng.r#gen::<cortado::Fr>());
        let λ_ab = Scalar::from(1234567u64);
        let Q_ab = (G * cortado::Fr::from(1234567u64)).into_affine();
        let (qa_x, qa_y) = xy(&Q_a);
        let witnesses = [
            Witness::FreeWires(qa_x, qa_y),
            Witness::FreeWires(λ_ab, Scalar::from(9u64)),
            Witness::Honest,
        ];
        assert!(!level0_verifies(
            guess,
            λ_ab,
            Q_a,
            Q_ab,
            Q_b,
            Witness::Honest,
            witnesses
        ));
    }

    /// A level-0 proof whose one decomposition of λ_a holds the bits of λ_a + ℓ, walked honestly
    /// for both the leaf key and the DH. Sharing the bits already makes the two use one integer;
    /// the range check still rejects an integer at or above ℓ, which a later proof decomposing the
    /// same commitment could read differently.
    #[test]
    fn v2_rejects_level_proof_with_aliased_bits() {
        let mut rng = rand::thread_rng();
        let G = CortadoAffine::generator();
        let Q_b = (G * rng.r#gen::<cortado::Fr>()).into_affine();
        let λ_a = Scalar::random(&mut rng);
        // the walks compute with K = λ_a + ℓ
        let aliased = bits_of(λ_a, Witness::Aliased);
        let K = cortado::Fr::from_le_bytes_mod_order(&aliased.to_bytes_le());
        assert_ne!(K, scalar_to_fr(&λ_a));
        let Q_a = (G * K).into_affine();
        let λ_ab = xy(&(Q_b * K).into_affine()).0;
        let Q_ab = (G * scalar_to_fr(&λ_ab)).into_affine();
        assert!(!level0_verifies(
            λ_a,
            λ_ab,
            Q_a,
            Q_ab,
            Q_b,
            Witness::Aliased,
            [Witness::Honest; 3]
        ));
    }
}
