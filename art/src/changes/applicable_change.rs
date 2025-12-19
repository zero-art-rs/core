use crate::errors::ArtError;

/// A trait for ART change that can be applied to the ART.
///
/// This trait represents an ability of change to update ART tree `art` (instance of type `T`).
///
/// # Type Parameters
/// * `T` – The type of the ART tree type being updated.
pub trait ApplicableChange<T, R> {
    /// Apply a change to the provided `art`. May return some auxiliary data of type `R`.
    fn apply(&self, art: &mut T) -> Result<R, ArtError>;
}
