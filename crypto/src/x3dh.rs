use crate::CryptoError;
use hkdf;
use sha3::Sha3_256;
use zkp::ark_ec::{AffineRepr, CurveGroup};

/// Computes the X3DH shared secret using the provided keys for Alice
pub fn x3dh_a<G: AffineRepr>(
    ika: G::ScalarField,
    eka: G::ScalarField,
    ikb: G,
    ekb: G,
) -> Result<[u8; 32], CryptoError> {
    let dh1 = ekb * ika;
    let dh2 = ikb * eka;
    let dh3 = ekb * eka;
    let mut dh = Vec::new();

    dh1.into_affine().serialize_compressed(&mut dh)?;
    dh2.into_affine().serialize_compressed(&mut dh)?;
    dh3.into_affine().serialize_compressed(&mut dh)?;
    let h = hkdf::Hkdf::<Sha3_256>::new(Some(b"x3dh-hkdf"), &dh);
    let mut okm = [0u8; 32];
    h.expand(&[], &mut okm)?;
    Ok(okm)
}

/// Computes the X3DH shared secret using the provided keys for Alice
pub fn x3dh_b<G: AffineRepr>(
    ika: G::ScalarField,
    eka: G::ScalarField,
    ikb: G,
    ekb: G,
) -> Result<[u8; 32], CryptoError> {
    let dh2 = ekb * ika;
    let dh1 = ikb * eka;
    let dh3 = ekb * eka;
    let mut dh = Vec::new();

    dh1.into_affine().serialize_compressed(&mut dh)?;
    dh2.into_affine().serialize_compressed(&mut dh)?;
    dh3.into_affine().serialize_compressed(&mut dh)?;
    let h = hkdf::Hkdf::<Sha3_256>::new(Some(b"x3dh-hkdf"), &dh);
    let mut okm = [0u8; 32];
    h.expand(&[], &mut okm)?;
    Ok(okm)
}

mod test {
    use super::*;
    use cortado;
    use rand;
    use zkp::ark_ff::UniformRand as _;
    #[test]
    fn test_x3dh() {
        let mut rng = rand::thread_rng();
        let ika = cortado::Fr::rand(&mut rng);
        let eka = cortado::Fr::rand(&mut rng);
        let ikb = cortado::Fr::rand(&mut rng);
        let ekb = cortado::Fr::rand(&mut rng);

        let Q_ika = (cortado::CortadoAffine::generator() * ika).into_affine();
        let Q_eka = (cortado::CortadoAffine::generator() * eka).into_affine();
        let Q_ikb = (cortado::CortadoAffine::generator() * ikb).into_affine();
        let Q_ekb = (cortado::CortadoAffine::generator() * ekb).into_affine();

        let shared_a = x3dh_a(ika, eka, Q_ikb, Q_ekb).expect("Failed to compute X3DH for Alice");
        let shared_b = x3dh_b(ikb, ekb, Q_ika, Q_eka).expect("Failed to compute X3DH for Bob");

        assert_eq!(shared_a, shared_b, "Shared secrets do not match");
    }
}
