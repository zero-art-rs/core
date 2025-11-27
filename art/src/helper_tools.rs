use crate::art::{PrivateArt, ProverArtefacts};
use crate::changes::ApplicableChange;
use crate::changes::branch_change::BranchChangeType;
use crate::errors::ArtError;
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
pub fn iota_function<G>(point: &G) -> Result<G::ScalarField, ArtError>
where
    G: AffineRepr + CanonicalSerialize + CanonicalDeserialize,
    G::BaseField: PrimeField,
{
    let x = point.x().ok_or(ArtError::XCoordinate)?;
    let secret = Scalar::from_bytes_mod_order((&x.into_bigint().to_bytes_le()[..]).try_into()?);

    Ok(G::ScalarField::from_le_bytes_mod_order(&secret.to_bytes()))
}

/// Recompute artefacts using given `secret_key` as leaf secret key, and provided `co_path`
/// public keys. `co_path` values are ordered from the leaves, to the root.
pub fn recompute_artefacts<G>(
    secret_key: G::ScalarField,
    co_path: &[G],
) -> Result<ProverArtefacts<G>, ArtError>
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

/// If Some(.), return first 8 chars from the string with three following dots. Else return
/// None as string.
pub(crate) fn prepare_short_marker_for_option<T>(full_marker: &Option<T>) -> String
where
    T: ToString,
{
    if let Some(full_marker) = full_marker {
        full_marker.to_string().chars().take(8).collect::<String>() + "..."
    } else {
        "None...".to_string()
    }
}

/// apply key update change to the provided `art` tree, with the given leaf `secret_key`.
pub(crate) fn inner_apply_own_key_update<G>(
    art: &mut PrivateArt<G>,
    secret_key: G::ScalarField,
) -> Result<G::ScalarField, ArtError>
where
    G: AffineRepr,
    G::BaseField: PrimeField,
{
    let path = art.node_index().get_path()?;
    let co_path = art.public_art().co_path(&path)?;
    let artefacts = recompute_artefacts(secret_key, &co_path)?;

    let key_update_change =
        artefacts.derive_branch_change(BranchChangeType::UpdateKey, art.node_index().clone())?;
    key_update_change.apply(&mut art.public_art)?;

    art.secrets.update(&artefacts.secrets, false)?;

    Ok(*artefacts
        .secrets
        .last()
        .ok_or(ArtError::InvalidBranchChange)?)
}
