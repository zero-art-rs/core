use ark_ff::Field;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use ark_std::{One, UniformRand, Zero};
use rand;
use serde_bytes::ByteBuf;

// return random ScalarField element, which isn't zero or one
pub fn random_non_neutral_scalar_field_element<F: Field>() -> F {
    let mut rng = StdRng::seed_from_u64(rand::random());

    let mut k = F::zero();
    while k.is_one() || k.is_zero() {
        k = F::rand(&mut rng);
    }

    k
}

/// Adapter for serialisation of arkworks-compatible types using CanonicalSerialize
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

pub fn create_random_secrets<F: Field>(size: usize) -> Vec<F> {
    let mut rng = &mut StdRng::seed_from_u64(rand::random());

    (0..size).map(|_| F::rand(&mut rng)).collect()
}
