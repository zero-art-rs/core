use crate::art::ProverArtefacts;
use crate::errors::ARTError;
use ark_ec::{AffineRepr, CurveGroup};
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
    a.serialize_with_mode(&mut bytes, Compress::Yes)
        .map_err(serde::ser::Error::custom)?;
    s.serialize_bytes(&bytes)
}
/// Adapter for deserialization of arkworks-compatible types using CanonicalDeserialize
pub fn ark_de<'de, D, A: CanonicalDeserialize>(data: D) -> Result<A, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let s: ByteBuf = serde::de::Deserialize::deserialize(data)?;
    let a = A::deserialize_with_mode(s.as_slice(), Compress::Yes, Validate::Yes);
    a.map_err(serde::de::Error::custom)
}

/// Iota function is a function which converts a point to scalar field element. It can
/// be any function. Here, th function takes x coordinate of affine representation of a point.
/// If the base field of curve defined on extension of a field, we take the first coefficient.
pub fn iota_function<G>(point: &G) -> Result<G::ScalarField, ARTError>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    let x = point.x().ok_or(ARTError::XCoordinateError)?;
    let secret = Scalar::from_bytes_mod_order((&x.into_bigint().to_bytes_le()[..]).try_into()?);

    Ok(G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes()))
}

/// Recompute artefacts using given `secret_key` as leaf secret key, and provided `co_path`
/// public keys. `co_path` values are ordered from the leaves, to the root.
pub fn recompute_artefacts<G>(
    secret_key: G::ScalarField,
    co_path: &[G],
) -> Result<ProverArtefacts<G>, ARTError>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    let mut ark_secret = secret_key;

    let mut secrets: Vec<G::ScalarField> = vec![secret_key];
    let mut path: Vec<G> = vec![G::generator().mul(ark_secret).into_affine()];
    for public_key in co_path {
        ark_secret = iota_function(&public_key.mul(ark_secret).into_affine())?;
        secrets.push(ark_secret);
        path.push(G::generator().mul(ark_secret).into_affine());
    }

    let artefacts = ProverArtefacts {
        path,
        co_path: co_path.to_vec(),
        secrets,
    };

    Ok(artefacts)
}

/// Return first 8 chars from the string with three following dots.
pub(crate) fn prepare_short_marker(full_marker: &str) -> String {
    full_marker.chars().take(8).collect::<String>() + "..."
}
