//! Errors produced while validating a [`CoreSpec`](crate::CoreSpec) and
//! materializing it into a synthetic ELF core dump.

use thiserror::Error;

/// Result alias for the testkit builder API.
pub type Result<T> = std::result::Result<T, BuilderError>;

/// A spec is rejected before any bytes are produced when it cannot be
/// materialized into a well-formed, self-consistent core.
#[derive(Debug, Error)]
pub enum BuilderError {
    #[error("object `{label}` has size {size}, below the minimum 0x10-byte user region")]
    ObjectTooSmall { label: String, size: usize },

    #[error("duplicate object label `{0}`")]
    DuplicateLabel(String),

    #[error("pointer field of object `{label}` at offset 0x{offset:x} does not fit in its {size}-byte user region")]
    PointerOutOfBounds { label: String, offset: usize, size: usize },

    #[error("target label `{0}` does not match any spec object")]
    UnknownTarget(String),

    #[error("root slot at stack address 0x{address:x} falls outside the stack region [0x{stack_base:x}, 0x{stack_end:x})")]
    RootOutsideStack { address: u64, stack_base: u64, stack_end: u64 },

    #[error("heap region [0x{heap_base:x}, 0x{heap_end:x}) cannot fit the chunk chain and a top chunk")]
    HeapLayout { heap_base: u64, heap_end: u64 },

    #[error("stack region [0x{stack_base:x}, 0x{stack_end:x}) is too small to hold its root slots")]
    StackLayout { stack_base: u64, stack_end: u64 },

    #[error("spec values are not 16-byte aligned as required: {field} = 0x{value:x}")]
    Misaligned { field: String, value: u64 },

    #[error("core cannot be written: {0}")]
    Io(#[from] std::io::Error),

    #[error("manifest cannot be serialized: {0}")]
    Json(#[from] serde_json::Error),
}
