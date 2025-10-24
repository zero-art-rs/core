use crate::cred::Credential;
use ark_ed25519::EdwardsAffine as Ed25519Affine;
use bulletproofs::PedersenGens;
use cortado::{CortadoAffine, Fr};
use zkp::toolbox::cross_dleq::PedersenBasis;
use zkp::toolbox::dalek_ark::ark_to_ristretto255;

pub enum ZeroArtEligibility {
    Owner(Fr),                    // owner of the group, could perform AddMember, RemoveMember
    Member(Fr), // just normal member of the group, needed for UpdateKey & ConfirmRemove ops.
    CredentialHolder(Credential), // holder of a credential, needed for anonymous AddMember & RemoveMember ops.
}

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

pub struct ZeroArtProverEngine<'a> {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
    pub(crate) old_leaf_secret: Option<Fr>,
    pub(crate) ad: &'a [u8],
}

impl<'a> ZeroArtProverEngine<'a> {
    pub fn new(
        ad: &'a [u8],
        basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
        options: ZeroArtEngineOptions,
    ) -> Self {
        let pc_gens = PedersenGens {
            B: ark_to_ristretto255(basis.G_2).unwrap(),
            B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
        };
        Self {
            ad,
            basis,
            pc_gens,
            old_leaf_secret: None,
            options,
        }
    }

    pub fn set_old_leaf_secret(&mut self, secret: Fr) {
        self.old_leaf_secret = Some(secret);
    }
}

pub struct ZeroArtVerifierEngine<'a> {
    pub(crate) basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
    pub(crate) pc_gens: PedersenGens,
    pub(crate) options: ZeroArtEngineOptions,
    pub(crate) ad: &'a [u8],
}

impl<'a> ZeroArtVerifierEngine<'a> {
    pub fn new(
        ad: &'a [u8],
        basis: PedersenBasis<CortadoAffine, Ed25519Affine>,
        options: ZeroArtEngineOptions,
    ) -> Self {
        let pc_gens = PedersenGens {
            B: ark_to_ristretto255(basis.G_2).unwrap(),
            B_blinding: ark_to_ristretto255(basis.H_2).unwrap(),
        };
        Self {
            ad,
            basis,
            pc_gens,
            options,
        }
    }
}
