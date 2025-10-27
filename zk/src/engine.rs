use crate::cred::Credential;
use crate::eligibility::*;
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use bulletproofs::PedersenGens;
use cortado::{CortadoAffine, Fr};
use curve25519_dalek::Scalar;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ark_to_ristretto255;

/// Engine options for ZeroArt proof system, currently supports setting of multi-threaded mode and scalar multiplication gadget version (1 or 2)
pub struct ZeroArtEngineOptions {
    pub multi_threaded: bool, // turn on multi-threaded mode, reducing proof generation time but increasing proof size, verifier must use the same mode
    pub scalar_mul_gadget_ver: u8,
}

impl Default for ZeroArtEngineOptions {
    fn default() -> Self {
        Self {
            multi_threaded: true,
            scalar_mul_gadget_ver: 2,
        }
    }
}

pub struct ZeroArtProverEngine {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
}

pub struct ZeroArtProverContext<'a> {
    pub(crate) engine: &'a ZeroArtProverEngine,
    pub(crate) ad: &'a [u8],
    pub(crate) eligibility: EligibilityArtefact,
}

impl ZeroArtProverEngine {
    /// Creates a new prover engine, could be stored in the global state
    pub fn new(
        basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
        options: ZeroArtEngineOptions,
    ) -> Self {
        let pc_gens = PedersenGens {
            B: ark_to_ristretto255(basis.G_2).unwrap(),
            B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
        };
        Self {
            basis,
            pc_gens,
            options,
        }
    }

    /// Starts a new proof context, takes associated data `ad` and eligibility options `eligibility`
    pub fn new_context<'a>(
        &'a self,
        ad: &'a [u8],
        eligibility: EligibilityArtefact,
    ) -> ZeroArtProverContext<'a> {
        ZeroArtProverContext {
            engine: self,
            ad,
            eligibility,
        }
    }
}

pub struct ZeroArtVerifierEngine {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
}

impl ZeroArtVerifierEngine {
    /// Creates a new verifier engine, could be stored in the global state
    pub fn new(
        basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
        options: ZeroArtEngineOptions,
    ) -> Self {
        let pc_gens = PedersenGens {
            B: ark_to_ristretto255(basis.G_2).unwrap(),
            B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
        };
        Self {
            basis,
            pc_gens,
            options,
        }
    }

    /// Creates a new verification context
    pub fn new_context<'a>(
        &'a self,
        ad: &'a [u8],
        eligibility: EligibilityRequirement,
    ) -> ZeroArtVerifierContext<'a> {
        ZeroArtVerifierContext {
            engine: self,
            ad,
            eligibility,
        }
    }
}

pub struct ZeroArtVerifierContext<'a> {
    pub(crate) engine: &'a ZeroArtVerifierEngine,
    pub(crate) ad: &'a [u8],
    pub(crate) eligibility: EligibilityRequirement,
}
