use ark_ec::short_weierstrass::SWCurveConfig as _;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::LinearCombination;

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

/// Constrain that R = P - Q
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
    