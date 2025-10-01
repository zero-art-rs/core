use ark_ff::{
    BigInteger, PrimeField,
    fields::{Fp256, MontBackend, MontConfig},
};
use curve25519_dalek::Scalar;

#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "5"]
pub struct FqConfig;
pub type Fq = Fp256<MontBackend<FqConfig, 4>>;

pub trait FromScalar {
    fn from_scalar(scalar: Scalar) -> Self;
}

pub trait ToScalar {
    fn into_scalar(&self) -> Scalar;
}

impl FromScalar for Fq {
    fn from_scalar(scalar: Scalar) -> Self {
        let bytes: [u8; 32] = scalar.to_bytes();

        Fq::from_le_bytes_mod_order(&bytes)
    }
}

impl ToScalar for Fq {
    fn into_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order((&self.into_bigint().to_bytes_le()[..]).try_into().unwrap())
    }
}
