#![allow(non_snake_case)]

use std::borrow::BorrowMut;

use ark_ec::short_weierstrass::SWCurveConfig as _;
use bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSError, Variable, Verifier};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::LinearCombination;
use rand::thread_rng;
use merlin::Transcript;

use crate::art::R1CSProof;
use crate::curve::cortado::{self, ToScalar as _};

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<u64>
}

#[derive(Copy, Clone, Debug)]
pub struct AllocatedScalar {
    pub variable: Variable,
    pub assignment: Option<Scalar>
}

impl AllocatedScalar {
    pub fn new(variable: Variable, assignment: Option<Scalar>) -> Self {
        return Self { variable, assignment }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct AllocatedPoint {
    pub x: AllocatedScalar,
    pub y: AllocatedScalar,
}

pub trait ProversAllocatableCortado: ConstraintSystem {
    fn allocate_scalar(&mut self, value: Scalar) -> Result<(AllocatedScalar, CompressedRistretto), R1CSError>;
    fn allocate_point(&mut self, x: Scalar, y: Scalar) -> Result<(AllocatedPoint, (CompressedRistretto, CompressedRistretto)), R1CSError>;
}

impl<'g, T: BorrowMut<Transcript>> ProversAllocatableCortado for Prover<'g, T> {
    fn allocate_scalar(&mut self, value: Scalar) -> Result<(AllocatedScalar, CompressedRistretto), R1CSError> {
        let (value_comm, value_var) = self.commit(value, Scalar::random(&mut thread_rng()));
        let value_var = AllocatedScalar::new(value_var, Some(value));
        Ok((value_var, value_comm))
    }
    fn allocate_point(&mut self, x: Scalar, y: Scalar) -> Result<(AllocatedPoint, (CompressedRistretto, CompressedRistretto)), R1CSError> {
        let (x_comm, x_var) = self.commit(x, Scalar::random(&mut thread_rng()));
        let (y_comm, y_var) = self.commit(y, Scalar::random(&mut thread_rng()));
        let Q = AllocatedPoint {
            x: AllocatedScalar::new(x_var, Some(x)),
            y: AllocatedScalar::new(y_var, Some(y)),
        };
        Ok((Q, (x_comm, y_comm)))
    }
}

pub trait VerifiersAllocatableCortado: ConstraintSystem {
    fn allocate_scalar(&mut self, comm: CompressedRistretto) -> Result<AllocatedScalar, R1CSError>;
    fn allocate_point(&mut self, x_comm: CompressedRistretto, y_comm: CompressedRistretto) -> Result<AllocatedPoint, R1CSError>;
}

impl<T: BorrowMut<Transcript>> VerifiersAllocatableCortado for Verifier<T> {
    fn allocate_scalar(&mut self, comm: CompressedRistretto) -> Result<AllocatedScalar, R1CSError> {
        let x_var = self.commit(comm);
        let x = AllocatedScalar::new(x_var, None);
        Ok(x)
    }
    fn allocate_point(&mut self, x_comm: CompressedRistretto, y_comm: CompressedRistretto) -> Result<AllocatedPoint, R1CSError> {
        let x_var = self.commit(x_comm);
        let y_var = self.commit(y_comm);
        let Q = AllocatedPoint {
            x: AllocatedScalar::new(x_var, None),
            y: AllocatedScalar::new(y_var, None),
        };
        Ok(Q)
    }
}

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn positive_no_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    bit_size: usize) -> Result<(), R1CSError> {
    let mut constraint_v = vec![(v.variable, -Scalar::ONE)];
    let mut exp_2 = Scalar::ONE;
    for i in 0..bit_size {
        // Create low-level variables and add them to constraints

        let (a, b, o) = cs.allocate_multiplier(v.assignment.map(|q| {
            let bit: u64 = (q >> i) & 1;
            ((1 - bit).into(), bit.into())
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        constraint_v.push((b, exp_2)  );
        exp_2 = exp_2 + exp_2;
    }

    // Enforce that -v + Sum(b_i * 2^i, i = 0..n-1) = 0 => Sum(b_i * 2^i, i = 0..n-1) = v
    cs.constrain(constraint_v.iter().collect());

    Ok(())
}

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(cs: &mut CS, lc: LinearCombination, scalar: &Scalar) {
    cs.constrain(lc - LinearCombination::from(*scalar));
}

/// Constrain that R = P - Q for Cortado points
pub fn co_linear_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    P: AllocatedPoint,
    Q: AllocatedPoint,
    R: AllocatedPoint,
) -> Result<(), R1CSError> {
    let (w_a, w_b) = ( cortado::Parameters::COEFF_A.into_scalar(), cortado::Parameters::COEFF_B.into_scalar());
    
    let (x1, y1) = (P.x.variable, P.y.variable);
    let (x2, y2) = (Q.x.variable, Q.y.variable);
    let (x3, y3) = (R.x.variable, R.y.variable);
    let (_, _, y_sqr) = cs.multiply(y3.into(), y3.into());
    let (_, _, x_sqr) = cs.multiply(x3.into(), x3.into());
    let (_, _, x_cube) = cs.multiply(x3.into(), x_sqr.into());

    let curve_eq = y_sqr - (x_cube + w_a * x3 + w_b);
    cs.constrain(curve_eq);

    // (y1 + y3) * (x2 - x3) = (y3 - y2) * (x1 - x3)
    let (_, _, lhs) = cs.multiply(LinearCombination::from(y1) + LinearCombination::from(y3), LinearCombination::from(x2) - LinearCombination::from(x3));
    let (_, _, rhs) = cs.multiply(LinearCombination::from(y3) - LinearCombination::from(y2), LinearCombination::from(x1) - LinearCombination::from(x3));
    
    cs.constrain(lhs - rhs);
    
    Ok(())
}

pub fn set_non_membership_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    x: AllocatedScalar,
    S: Vec<Scalar>,
) -> Result<(), R1CSError> {
    let mut l: LinearCombination = Scalar::ONE.into();
    for s in S {
        let (_, _, o) = cs.multiply(l.clone(), x.variable - s);
        l = o.into();
    }
    let l_inv = cs.allocate(cs.eval(&l).map(|v| v.invert()))?;
    let (_, _, o) = cs.multiply(l, l_inv.into());
    // Output wire should have value 1
    cs.constrain(o - Scalar::ONE);
    Ok(())
}

#[test]
fn set_non_membership_gadget_test() {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(128, 1);
    let mut prover_transcript = Transcript::new(b"test");
   

    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let (x, x_com) = prover.allocate_scalar(Scalar::from(8u64)).unwrap();

    let S = vec![Scalar::from(1u64), Scalar::from(2u64), Scalar::from(3u64) ];

    set_non_membership_gadget(&mut prover, x, S.clone()).unwrap();

    let proof = prover.prove(&bp_gens).unwrap();
    {
        let mut verifier_transcript = Transcript::new(b"test");
        let mut verifier = Verifier::new(&mut verifier_transcript);
        let x = verifier.allocate_scalar(x_com).unwrap();

        set_non_membership_gadget(&mut verifier, x, S).unwrap();

        verifier.verify(&proof, &pc_gens, &bp_gens).unwrap();
    }
}
