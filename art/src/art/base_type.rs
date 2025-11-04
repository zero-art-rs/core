use ark_ec::AffineRepr;
use crate::art::art_types::{PrivateArt, PublicArt};

pub(crate) trait PublicArtHolder<G>
where
    G: AffineRepr,
{
    fn public_art(&self) -> &PublicArt<G>;
    fn mut_public_art(&mut self) -> &mut PublicArt<G>;
}

pub(crate) trait PrivateArtHolder<G>
where
    G: AffineRepr,
{
    fn private_art(&self) -> &PrivateArt<G>;
    fn mut_private_art(&mut self) -> &mut PrivateArt<G>;
}

pub(crate) trait ArtHolder<T> {
    fn get_art(&self) -> &T;
    fn get_mut_art(&mut self) -> &mut T;
}
