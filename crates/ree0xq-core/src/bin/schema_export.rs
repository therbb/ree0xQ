//! Emit the canonical JSON Schema for [`CryptoInventoryEvent`] to
//! stdout. Used by CI to publish a stable artifact next to each
//! release, and by the React UI's schema validator.
//!
//! Build / run:
//!     cargo run --features schema --bin schema-export > schema.json

use ree0xq_core::CryptoInventoryEvent;
use schemars::schema_for;

fn main() {
    let schema = schema_for!(CryptoInventoryEvent);
    println!("{}", serde_json::to_string_pretty(&schema).unwrap());
}
