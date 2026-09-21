//! `ree0xq-qkd` — QKD observability agent and reference KME emulator.
//!
//! Two roles in one crate:
//!
//! 1. **Collector.** Polls one or more ETSI GS QKD 014 Key Management
//!    Entities (KMEs) on a configurable cadence, observes link status,
//!    and emits `crypto_inventory_event` records of kind `QkdLink` and
//!    `QkdKme`. Cooperating Secure Application Entities (SAEs) can
//!    attach the resulting `ChannelProtection` block to session events
//!    they emit through other ree0xQ modules.
//!
//! 2. **Reference KME emulator.** A spec-faithful implementation of
//!    ETSI GS QKD 014 v1.1.1 Key Delivery API backed by a synthetic
//!    key generator. Released alongside the collector so that
//!    practitioners without access to physical QKD hardware can
//!    exercise QKD-aware software end-to-end. Supports replay
//!    scenarios (link degradation, hard failure, stale PSK,
//!    bifurcated SAE views) used in the paper's Study 2.
//!
//! Both roles share the [`etsi014`] type module so that the wire
//! contract is enforced by the compiler rather than by convention.
//!
//! # Layering
//!
//! ```text
//!  ┌─────────────────────────────────────────────┐
//!  │   bin/collector.rs        bin/kme_emulator.rs   │
//!  └────────────┬──────────────────────┬─────────────┘
//!               │                      │
//!         ┌─────▼─────┐          ┌─────▼─────┐
//!         │ collector │          │ emulator  │
//!         └─────┬─────┘          └─────┬─────┘
//!               │                      │
//!               └──────────┬───────────┘
//!                          ▼
//!                      etsi014  (request / response types,
//!                                URL paths, error mapping)
//! ```

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod collector;
pub mod emulator;
pub mod etsi014;
pub mod replay;

/// Identifier for this agent in the `source_module` field of emitted
/// events. Constant so the value cannot drift across the codebase.
pub const SOURCE_MODULE: &str = "ree0xq-qkd";
