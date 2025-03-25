use crate::curve::g2::{Fq, Fr};
use ark_ec::{models::CurveConfig, short_weierstrass::*};
use ark_ff::{Field, MontFp};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type G2Affine = Affine<Parameters>;
pub type G2Projective = Projective<Parameters>;

impl CurveConfig for Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;

    /// COFACTOR = 1
    const COFACTOR: &'static [u64] = &[0x1];

    /// COFACTOR_INV = COFACTOR^{-1} mod r = 1
    #[rustfmt::skip]
    const COFACTOR_INV: Fr = Fr::ONE;
}

impl SWCurveConfig for Parameters {
    /// COEFF_A = 3
    const COEFF_A: Fq = MontFp!("3");

    /// COEFF_B = 1922818355259392696732836237061565820365600586068756122728142679266880691480
    const COEFF_B: Fq =
        MontFp!("1922818355259392696732836237061565820365600586068756122728142679266880691480");

    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const GENERATOR: Affine<Self> = Affine::new_unchecked(G_GENERATOR_X, G_GENERATOR_Y);

    #[inline(always)]
    fn mul_by_a(x: Self::BaseField) -> Self::BaseField {
        &x + &x + &x
    }
}

pub const G_GENERATOR_X: Fq = MontFp!("5113957452986742454094433272326380516801473643952508191581880271902332482582");

pub const G_GENERATOR_Y: Fq = MontFp!("5171267151717298187039489040680477076031932900992525155183606237639729989348");
