//! In-memory adapters implementing the `crate::ports` traits, for fast unit tests.
//! Compiled only for `cfg(test)` or the `test-utils` feature so integration tests and
//! downstream crates can reuse them.

pub mod store;

pub use store::InMemoryStore;
