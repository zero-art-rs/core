//! This crate provide ART changes types and traits to work with them.

pub mod aggregations;
mod applicable_change;
pub mod branch_change;
mod provable_change;
mod verifiable_change;

pub use applicable_change::ApplicableChange;
pub use provable_change::ProvableChange;
pub use verifiable_change::VerifiableChange;
