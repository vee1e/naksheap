//! naksheap-allocator-heuristics
//!
//! Allocator-aware heap carving over a parsed core dump address space.
//!
//! Given a parsed [`AddressSpace`] (an ELF core or minidump image), this crate
//! recovers the heap objects stored by glibc's ptmalloc allocator: their
//! addresses, sizes, and allocated/freed state. It does so by locating the
//! arenas (primarily `main_arena` via its self-looping `next` pointer) and
//! walking the chunk headers that ptmalloc writes inline in anonymous writable
//! heap mappings.
//!
//! The implementation is intentionally heuristic: it never panics on garbage
//! and gracefully degrades to whatever chunk boundaries it can validate.

pub mod glibc;

use naksheap_core_parse::AddressSpace;

/// Allocator-level state of a carved heap object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectState {
    /// The chunk is live (its successor has `PREV_INUSE` set).
    Allocated,
    /// The chunk was returned to the allocator (successor's `PREV_INUSE` clear).
    Freed,
    /// The chunk was served by `mmap` (`IS_MMAPPED` flag).
    Mmap,
    /// State could not be determined.
    Unknown,
}

/// Why a chunk was classified as [`ObjectState::Freed`]. Carried into the
/// object graph so evidence lines state the actual mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FreedReason {
    /// The successor chunk's `PREV_INUSE` bit is clear (bin/unsorted free).
    PrevInuseClear,
    /// The chunk's user address appears in the tcache free lists.
    Tcache,
    /// The chunk's user address appears in an arena fastbin chain.
    Fastbin,
}

/// A single carved heap object (the user region of a ptmalloc chunk).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Object {
    /// Address of the object's user data (chunk header + `0x10`).
    pub addr: u64,
    /// Usable size of the object in bytes (`(size & !0xF) - 0x10`).
    pub size: u64,
    /// Allocator state of the object.
    pub state: ObjectState,
    /// Address of the arena that governs this object, when known.
    pub arena: Option<u64>,
    /// Address of the chunk header (`addr - 0x10`).
    pub chunk_header: u64,
    /// Why the object was marked freed (best-effort; `None` when allocated).
    pub freed_reason: Option<FreedReason>,
}

/// A discovered ptmalloc arena.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ArenaInfo {
    /// Address of the `malloc_state` structure.
    pub addr: u64,
    /// Size of the heap region the arena's `top` points into.
    pub size: u64,
    /// Value of the arena's `top` field (points into an anonymous rw- heap).
    pub top: u64,
    /// `true` when this is `main_arena` (its `next` field self-loops).
    pub is_main: bool,
}

/// Result of carving an address space: arenas plus carved heap objects.
#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct HeapInventory {
    pub arenas: Vec<ArenaInfo>,
    pub objects: Vec<Object>,
}

/// Carves heap objects out of `image` using glibc ptmalloc heuristics.
///
/// Never panics: if the image carries no parseable ptmalloc metadata, an empty
/// [`HeapInventory`] is returned.
pub fn carve(image: &dyn AddressSpace) -> HeapInventory {
    glibc::carve(image)
}
