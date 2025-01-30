//! WIP

mod backend;
mod gcm;
mod stream;

pub use gcm::*;
pub use stream::*;

/// The size in bytes of a SNOV-V stream cipher and SNOW-V-GCM
/// AEAD key.
pub const KEY_SIZE: usize = 32;
