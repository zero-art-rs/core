use ark_ff::{
    BigInteger as _, PrimeField as _,
    fields::{Fp256, MontBackend, MontConfig},
};
use curve25519_dalek::Scalar;

use crate::fq::{FromScalar, ToScalar};

#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240986995387936333955789609363939694262923"]
#[generator = "3"]
pub struct FrConfig;
pub type Fr = Fp256<MontBackend<FrConfig, 4>>;

impl FromScalar for Fr {
    fn from_scalar(scalar: Scalar) -> Self {
        let bytes: [u8; 32] = scalar.to_bytes();

        Fr::from_le_bytes_mod_order(&bytes)
    }
}

impl ToScalar for Fr {
    fn into_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order((&self.into_bigint().to_bytes_le()[..]).try_into().unwrap())
    }
}
