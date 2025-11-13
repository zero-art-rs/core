use crate::art::ProverArtefacts;
use crate::art_node::{ArtNode, LeafStatus};
use crate::changes::branch_change::BranchChangeType;
use crate::errors::ArtError;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed25519::EdwardsAffine;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};
use bulletproofs::PedersenGens;
use cortado::CortadoAffine;
use curve25519_dalek::Scalar;
use serde_bytes::ByteBuf;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ristretto255_to_ark;
use zrt_zk::engine::{ZeroArtEngineOptions, ZeroArtProverEngine, ZeroArtVerifierEngine};
use crate::changes::aggregations::AggregationNode;
use crate::node_index::Direction;

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

pub(crate) fn default_proof_basis() -> PedersenBasis<CortadoAffine, EdwardsAffine> {
    let gens = PedersenGens::default();
    PedersenBasis::<CortadoAffine, EdwardsAffine>::new(
        CortadoAffine::generator(),
        CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y),
        ristretto255_to_ark(gens.B).unwrap(),
        ristretto255_to_ark(gens.B_blinding).unwrap(),
    )
}

pub(crate) fn default_verifier_engine() -> ZeroArtVerifierEngine {
    ZeroArtVerifierEngine::new(default_proof_basis(), ZeroArtEngineOptions::default())
}

pub(crate) fn default_prover_engine() -> ZeroArtProverEngine {
    ZeroArtProverEngine::new(default_proof_basis(), ZeroArtEngineOptions::default())
}

pub(crate) fn change_leaf_status_by_change_type<G>(
    target_node: &mut ArtNode<G>,
    change_type: &BranchChangeType,
) -> Result<(), ArtError>
where
    G: AffineRepr,
{
    let target_leaf_status = match change_type {
        BranchChangeType::UpdateKey => Some(LeafStatus::Active),
        BranchChangeType::AddMember => None,
        BranchChangeType::RemoveMember => Some(LeafStatus::Blank),
        BranchChangeType::Leave => Some(LeafStatus::PendingRemoval),
    };
    if let Some(target_leaf_status) = target_leaf_status {
        target_node.set_status(target_leaf_status)?;
    }

    Ok(())
}

/// Computes how many nodes in `marker_tree` on the given `path` are marked as updated.
pub(crate) fn compute_merge_bound(marker_tree: &AggregationNode<bool>, path: &[Direction]) -> Result<usize, ArtError> {
    let mut parent = marker_tree;
    let mut secrets_amount_to_merge = parent.data as usize;
    if parent.data {
        for (_, dir) in path.iter().enumerate() {
            parent = parent.get_child(*dir).ok_or(ArtError::PathNotExists)?;
            if parent.data {
                secrets_amount_to_merge += 1;
            } else {
                break;
            }
        }
    }

    Ok(secrets_amount_to_merge)
}
