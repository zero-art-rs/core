use ark_ec::AffineRepr;
use crate::art::{ArtProof, ProverNodeData, VerifierNodeData};
use crate::eligibility::*;
use ark_ed25519::{EdwardsAffine as Ed25519Affine, EdwardsAffine};
use bulletproofs::PedersenGens;
use cortado::{CortadoAffine, Fr};
use rand_core::CryptoRngCore;
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::{ark_to_ristretto255, ristretto255_to_ark};
use crate::aggregated_art::{ProverAggregationTree, VerifierAggregationTree};
use crate::errors::ZKError;

/// Engine options for ZeroArt proof system, currently supports setting of multi-threaded mode and scalar multiplication gadget version (1 or 2)
#[derive(Clone)]
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

#[derive(Clone)]
pub struct ZeroArtProverEngine {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
}

impl Default for ZeroArtProverEngine {
    fn default() -> Self {
        let gens = PedersenGens::default();
        let default_proof_basis = PedersenBasis::<CortadoAffine, EdwardsAffine>::new(
            CortadoAffine::generator(),
            CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y),
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );

        ZeroArtProverEngine::new(default_proof_basis, ZeroArtEngineOptions::default())
    }
}

#[derive(Clone)]
pub(crate) enum ProofType<'a> {
    Branch(&'a Vec<ProverNodeData<CortadoAffine>>),
    Aggregated(&'a ProverAggregationTree<CortadoAffine>)
}

#[derive(Clone)]
pub struct ZeroArtProverContext<'a> {
    pub(crate) engine: &'a ZeroArtProverEngine,
    pub(crate) ad: Option<&'a [u8]>,
    pub(crate) eligibility: EligibilityArtefact,
    pub(crate) proof_type: Option<ProofType<'a>>,
}


impl<'a> ZeroArtProverContext<'a> {
    pub fn with_ad(mut self, ad: &'a [u8]) -> Self {
        self.ad = Some(ad);
        self
    }

    pub fn for_branch(mut self, branch_nodes: &'a Vec<ProverNodeData<CortadoAffine>>) -> Self {
        self.proof_type = Some(ProofType::Branch(branch_nodes));
        self
    }

    pub fn for_aggregation(mut self, aggregated_tree: &'a ProverAggregationTree<CortadoAffine>) -> Self {
        self.proof_type = Some(ProofType::Aggregated(aggregated_tree));
        self
    }

    pub(crate) fn ad(&self) -> &[u8] {
        match self.ad {
            Some(ad) => ad,
            None => &[],
        }
    }

    pub fn prove<R>(&self, rng: &mut R) -> Result<ArtProof, ZKError>
    where
        R: CryptoRngCore,
    {
        match self.proof_type {
            Some(ProofType::Branch(branch_nodes)) => self.prove_singular(branch_nodes, rng),
            Some(ProofType::Aggregated(aggregated_tree)) => self.prove_aggregated(aggregated_tree, rng),
            None => self.prove_singular(&Vec::new(), rng)
        }
    }
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
    pub fn new_context(
        &self,
        eligibility: EligibilityArtefact,
    ) -> ZeroArtProverContext {
        ZeroArtProverContext {
            engine: &self,
            eligibility,
            ad: None,
            proof_type: None,
        }
    }
}

#[derive(Clone)]
pub struct ZeroArtVerifierEngine {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
}

impl Default for ZeroArtVerifierEngine {
    fn default() -> Self {
        let gens = PedersenGens::default();
        let default_proof_basis = PedersenBasis::<CortadoAffine, EdwardsAffine>::new(
            CortadoAffine::generator(),
            CortadoAffine::new_unchecked(cortado::ALT_GENERATOR_X, cortado::ALT_GENERATOR_Y),
            ristretto255_to_ark(gens.B).unwrap(),
            ristretto255_to_ark(gens.B_blinding).unwrap(),
        );

        ZeroArtVerifierEngine::new(default_proof_basis, ZeroArtEngineOptions::default())
    }
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
    pub fn new_context(
        &self,
        eligibility: EligibilityRequirement,
    ) -> ZeroArtVerifierContext {
        ZeroArtVerifierContext {
            engine: self,
            ad: None,
            eligibility,
            verification_type: None,
        }
    }
}

#[derive(Clone)]
pub(crate) enum VerificationType<'a> {
    Branch(&'a Vec<VerifierNodeData<CortadoAffine>>),
    Aggregated(&'a VerifierAggregationTree<CortadoAffine>)
}

pub struct ZeroArtVerifierContext<'a> {
    pub(crate) engine: &'a ZeroArtVerifierEngine,
    pub(crate) ad: Option<&'a [u8]>,
    pub(crate) eligibility: EligibilityRequirement,
    pub(crate) verification_type: Option<VerificationType<'a>>,
}

impl<'a> ZeroArtVerifierContext<'a> {
    pub fn with_associated_data(mut self, ad: &'a [u8]) -> Self {
        self.ad = Some(ad);
        self
    }

    pub fn for_branch(mut self, branch_nodes: &'a Vec<VerifierNodeData<CortadoAffine>>) -> Self {
        self.verification_type = Some(VerificationType::Branch(branch_nodes));
        self
    }

    pub fn for_aggregation(mut self, aggregated_tree: &'a VerifierAggregationTree<CortadoAffine>) -> Self {
        self.verification_type = Some(VerificationType::Aggregated(aggregated_tree));
        self
    }

    pub(crate) fn ad(&self) -> &[u8] {
        match self.ad {
            Some(ad) => ad,
            None => &[],
        }
    }

    pub fn verify(&self, proof: &ArtProof) -> Result<(), ZKError> {
        match self.verification_type {
            Some(VerificationType::Branch(branch_nodes)) => self.verify_singular(proof, branch_nodes),
            Some(VerificationType::Aggregated(aggregated_tree)) => self.verify_aggregated(aggregated_tree, proof),
            None => self.verify_singular(proof, &Vec::new())
        }
    }
}
