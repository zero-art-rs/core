use crate::{Fq, Fr};
use ark_ec::{models::CurveConfig, short_weierstrass::*};
use ark_ff::{Field, MontFp};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Parameters;

pub type CortadoAffine = Affine<Parameters>;
pub type CortadoProjective = Projective<Parameters>;

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
    type ZeroFlag = ();
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

pub const G_GENERATOR_X: Fq =
    MontFp!("5113957452986742454094433272326380516801473643952508191581880271902332482582");

pub const G_GENERATOR_Y: Fq =
    MontFp!("5171267151717298187039489040680477076031932900992525155183606237639729989348");

/// The alternative generator H, with no known discrete log with respect to the generator: x is
/// the first SHA-256("zero-art/cortado/alt-generator/v1" ‖ counter as 4 bytes, little-endian)
/// mod q, counter = 0, 1, ..., with x^3 + a·x + b a square (counter 2), and y is the square root
/// whose integer is even. `tests::alt_generator` recomputes it.
///
/// The scalar multiplication gadgets add their offsets on H, and they are sound only while
/// nobody knows that discrete log.
pub const ALT_GENERATOR_X: Fq =
    MontFp!("3201766159355692452011165711944731975415909527808596938942611998347728901470");

pub const ALT_GENERATOR_Y: Fq =
    MontFp!("5298902490966213458215399080871210807668381048944778696879685077438962522038");
