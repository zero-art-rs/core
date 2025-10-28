#![allow(non_snake_case)]
use crate::cred::{Credential, CredentialPresentationProof};
use crate::engine::{
    ZeroArtEngineOptions, ZeroArtProverContext, ZeroArtProverEngine, ZeroArtVerifierContext,
    ZeroArtVerifierEngine,
};
use crate::errors::ZKError;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError};
use cortado::{self, CortadoAffine, Fr, ToScalar};
use curve25519_dalek::Scalar;
use merlin::Transcript;
use zkp::CompactProof;
use zkp::toolbox::{
    FromBytes, SchnorrCS, ToBytes, prover::Prover as SigmaProver,
    verifier::Verifier as SigmaVerifier,
};

#[derive(Clone)]
pub(crate) enum EligibilityProof {
    Owner(CompactProof<cortado::Fr>),
    Member(CompactProof<cortado::Fr>),
    CredentialHolder(CredentialPresentationProof),
}

pub enum EligibilityArtefact {
    Member((Fr, CortadoAffine)), // just normal member of the group, needed for UpdateKey & ConfirmRemove ops.
    Owner((Fr, CortadoAffine)),  // owner of the group, could perform AddMember, RemoveMember
    CredentialHolder((Fr, Credential)), // holder of a credential, needed for anonymous AddMember & RemoveMember ops.
}

#[derive(Clone)]
pub enum EligibilityRequirement {
    Member(CortadoAffine), // requirement only for proof of leaf possession or group membership, public key is provided
    Previleged((CortadoAffine, Vec<Scalar>)), // requirement for the previleged rights
}

impl CanonicalSerialize for EligibilityProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        mut writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        match self {
            EligibilityProof::Owner(proof) => {
                0u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(&mut writer, compress)?;
            }
            EligibilityProof::Member(proof) => {
                1u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(&mut writer, compress)?;
            }
            EligibilityProof::CredentialHolder(proof) => {
                2u8.serialize_with_mode(&mut writer, compress)?;
                proof.serialize_with_mode(&mut writer, compress)?;
            }
        }

        Ok(())
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        match self {
            EligibilityProof::Owner(proof) | EligibilityProof::Member(proof) => {
                1 + proof.serialized_size(compress)
            }
            EligibilityProof::CredentialHolder(proof) => 1 + proof.serialized_size(compress),
        }
    }
}

impl ark_serialize::Valid for EligibilityProof {
    fn check(&self) -> Result<(), SerializationError> {
        // Validity check is performed during deserialization
        Ok(())
    }
}

impl CanonicalDeserialize for EligibilityProof {
    fn deserialize_with_mode<R: std::io::Read>(
        mut reader: R,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, SerializationError> {
        // Read variant tag
        let variant = u8::deserialize_with_mode(&mut reader, compress, validate)?;

        match variant {
            0 => {
                // Owner variant
                let proof = CompactProof::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(EligibilityProof::Owner(proof))
            }
            1 => {
                // Member variant
                let proof = CompactProof::deserialize_with_mode(&mut reader, compress, validate)?;
                Ok(EligibilityProof::Member(proof))
            }
            2 => {
                // CredentialHolder variant
                let proof = CredentialPresentationProof::deserialize_with_mode(
                    &mut reader,
                    compress,
                    validate,
                )?;
                Ok(EligibilityProof::CredentialHolder(proof))
            }
            _ => Err(SerializationError::InvalidData),
        }
    }
}

impl<'a> ZeroArtProverContext<'a> {
    pub(crate) fn prove_eligibility(&self) -> Result<EligibilityProof, ZKError> {
        Ok(match &self.eligibility {
            EligibilityArtefact::Owner((s, R)) => {
                let mut transcript = Transcript::new(b"eligibility");
                transcript.append_message(b"ad", self.ad);
                let mut prover: SigmaProver<CortadoAffine, Transcript, &mut Transcript> =
                    SigmaProver::new(b"ProofOfOwnership", &mut transcript);

                let (var_P, _) = prover.allocate_point(b"P", self.engine.basis.G_1);
                let var_s = prover.allocate_scalar(b"s", s.clone());
                let (var_R, _) = prover.allocate_point(b"R", R.clone());
                prover.constrain(var_R, vec![(var_s, var_P)]);

                let sigma_proof = prover.prove_compact();
                EligibilityProof::Owner(sigma_proof)
            }
            EligibilityArtefact::Member((s, R)) => {
                let mut transcript = Transcript::new(b"eligibility");
                transcript.append_message(b"ad", self.ad);
                let mut prover: SigmaProver<CortadoAffine, Transcript, &mut Transcript> =
                    SigmaProver::new(b"ProofOfMembership", &mut transcript);

                let (var_P, _) = prover.allocate_point(b"P", self.engine.basis.G_1);
                let var_s = prover.allocate_scalar(b"s", s.clone());
                let (var_R, _) = prover.allocate_point(b"R", R.clone());
                prover.constrain(var_R, vec![(var_s, var_P)]);

                let sigma_proof = prover.prove_compact();
                EligibilityProof::Member(sigma_proof)
            }
            EligibilityArtefact::CredentialHolder((s, cred)) => {
                EligibilityProof::CredentialHolder(cred.present(self.ad, s.clone(), vec![])?)
            }
        })
    }
}

impl<'a> ZeroArtVerifierContext<'a> {
    pub(crate) fn verify_eligibility(
        &self,
        eligibility_proof: &EligibilityProof,
    ) -> Result<(), ZKError> {
        match &self.eligibility {
            EligibilityRequirement::Member(pk) => match eligibility_proof {
                EligibilityProof::Member(proof) => {
                    let mut transcript = Transcript::new(b"eligibility");
                    transcript.append_message(b"ad", self.ad);
                    let mut verifier: SigmaVerifier<CortadoAffine, Transcript, &mut Transcript> =
                        SigmaVerifier::new(b"ProofOfMembership", &mut transcript);

                    let var_P = verifier.allocate_point(b"P", self.engine.basis.G_1)?;
                    let var_s = verifier.allocate_scalar(b"s");
                    let var_R = verifier.allocate_point(b"R", *pk)?;
                    verifier.constrain(var_R, vec![(var_s, var_P)]);
                    verifier.verify_compact(proof).map_err(|e| e.into())
                }
                _ => Err(ZKError::EligibilityError),
            },
            EligibilityRequirement::Previleged((owner_pk, revocation_list)) => {
                match eligibility_proof {
                    EligibilityProof::Owner(proof) => {
                        let mut transcript = Transcript::new(b"eligibility");
                        transcript.append_message(b"ad", self.ad);
                        let mut verifier: SigmaVerifier<
                            CortadoAffine,
                            Transcript,
                            &mut Transcript,
                        > = SigmaVerifier::new(b"ProofOfOwnership", &mut transcript);

                        let var_P = verifier.allocate_point(b"P", self.engine.basis.G_1)?;
                        let var_s = verifier.allocate_scalar(b"s");
                        let var_R = verifier.allocate_point(b"R", *owner_pk)?;
                        verifier.constrain(var_R, vec![(var_s, var_P)]);
                        verifier.verify_compact(proof).map_err(|e| e.into())
                    }
                    EligibilityProof::CredentialHolder(proof) => Credential::verify_presentation(
                        self.ad,
                        proof,
                        *owner_pk,
                        revocation_list.clone(),
                    )
                    .map_err(|e| e.into()),
                    _ => Err(ZKError::EligibilityError),
                }
            }
        }
    }
}
