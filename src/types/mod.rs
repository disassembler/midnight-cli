// Midnight-specific types
//
// This module contains datum structures and types specific to the Midnight Network.
// General-purpose types (like VersionedMultisig) belong in hayate.

pub mod federated_ops;

pub use federated_ops::{FederatedOpsDatum, ValidatorKeys};
