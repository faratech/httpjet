//! Compile-time extension registration point.
//!
//! An extension crate is linked by adding it to `crates/httpjet/Cargo.toml`,
//! then registered here in deterministic execution order. The shipped registry
//! is intentionally empty, so production behavior and cost are unchanged.

pub(crate) fn compiled_registry() -> hj_extension::ExtensionRegistry {
    hj_extension::ExtensionRegistry::new()
}
