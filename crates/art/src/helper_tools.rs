use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use curve25519_dalek::Scalar;
use serde_bytes::ByteBuf;

/// Adapter for serialization of arkworks-compatible types using CanonicalSerialize
pub fn ark_se<S, A: CanonicalSerialize>(a: &A, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut bytes = vec![];
    a.serialize_with_mode(&mut bytes, Compress::No)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}
/// Adapter for deserialization of arkworks-compatible types using CanonicalDeserialize
pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: ByteBuf = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::No, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

/// Iota function is a function which converts computed public secret to scalar field. It can
/// be any function. Here, th function takes x coordinate of affine representation of a point.
/// If the base field of curve defined on extension of a field, we take the first coefficient.
pub fn iota_function<G>(point: &G) -> Scalar
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    let x = point.x().unwrap();

    Scalar::from_bytes_mod_order((&x.into_bigint().to_bytes_le()[..]).try_into().unwrap())
}
