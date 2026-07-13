//! Ports (trait interfaces) that decouple the domain layer from concrete infrastructure.
//! See docs/IMPROVEMENT_PLAN.md (Phase 1). Production adapters are `impl Port for ConcreteType`
//! blocks next to each trait; in-memory test adapters live in `crate::test_adapters`.

pub mod store;
