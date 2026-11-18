//! Everything ca-api keeps — only encrypted, in the data folder, with a key that is never on the
//! disk.

pub(crate) mod data_folder;
pub mod journal;
pub(crate) mod legacy;
mod secure_storage;
mod state_model;

pub use secure_storage::*;
pub use state_model::*;
