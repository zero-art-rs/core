pub mod fq;
pub mod fr;
pub mod cortado;
pub use fq::*;
pub use fr::*;
pub use cortado::*;

#[cfg(test)]
mod tests;
