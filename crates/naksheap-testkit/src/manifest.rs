//! Ground-truth manifest types.
//!
//! A [`Manifest`] is the *expected* outcome of analyzing a synthetic core:
//! the allocator state, carved heap objects, roots, and pointer edges that a
//! correct heap-reconstruction pipeline (arena discovery -> chunk carving ->
//! pointer scan) must recover. Tests and downstream golden-file comparisons
//! assert that the pipeline's output equals this manifest.
//!
//! The `arena`/`object` shapes intentionally mirror
//! `naksheap-allocator-heuristics` (`ArenaInfo`/`Object`) so manifests can be
//! compared field-for-field with carved inventories.

use serde::Serialize;

/// Allocator state of a carved heap object, mirroring
/// `naksheap_allocator_heuristics::ObjectState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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

/// A discovered ptmalloc arena (mirrors `ArenaInfo`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestArena {
    /// Address of the `malloc_state` structure.
    pub addr: u64,
    /// Size of the heap region the arena's `top` points into.
    pub size: u64,
    /// Value of the arena's `top` field (points into an anonymous rw- heap).
    pub top: u64,
    /// `true` when this is `main_arena` (its `next` field self-loops).
    pub is_main: bool,
}

/// A carved heap object (mirrors `Object`, plus the spec label).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestObject {
    /// Address of the object's user data (chunk header + `0x10`).
    pub addr: u64,
    /// Usable size in bytes (`(size & !0xF) - 0x10`).
    pub size: u64,
    /// Allocator state of the object.
    pub state: ObjectState,
    /// Address of the governing arena.
    pub arena: u64,
    /// Address of the chunk header (`addr - 0x10`).
    pub chunk_header: u64,
    /// Semantic label from the spec that produced this object.
    pub label: String,
}

/// Where a root slot lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootKind {
    /// A word in the stack blob (a stack root).
    Stack,
    /// A general-purpose register that holds a heap pointer.
    Register,
}

/// A root: a word that points into the heap (or at a rodata target) and is a
/// valid starting point for a conservative pointer scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestRoot {
    /// Address of the slot holding the root (stack address or register index
    /// for `Register` roots).
    pub addr: u64,
    /// The pointer value stored in the slot.
    pub value: u64,
    /// Where the root lives.
    pub kind: RootKind,
    /// Label of the target object, when the value points into the heap.
    pub target_label: Option<String>,
}

/// Classification of a pointer edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Object -> object (heap pointer).
    Heap,
    /// Object -> file-backed rodata (vtable-like / string literal).
    Rodata,
}

/// A pointer edge a pointer scan is expected to recover: a word at
/// `(from_addr + offset)` holding `to_addr`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestEdge {
    /// Address of the source object.
    pub from_addr: u64,
    /// Label of the source object.
    pub from_label: String,
    /// Byte offset of the pointer inside the source user region.
    pub offset: usize,
    /// Address the pointer targets.
    pub to_addr: u64,
    /// Label of the target object, when the edge points into the heap.
    pub to_label: Option<String>,
    /// Classification of the edge.
    pub kind: EdgeKind,
}

/// The complete ground truth for one synthetic core fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Manifest {
    /// Architecture pointer width in bytes (always 8 for this builder).
    pub pointer_width: u8,
    /// `pid` embedded in `NT_PRSTATUS`.
    pub pid: i32,
    /// Process name from `NT_PRPSINFO` (`pr_fname`).
    pub process_name: String,
    /// Command line from `NT_PRPSINFO` (`pr_psargs`).
    pub command_line: String,
    /// Main executable path, as the parser infers it from `NT_FILE`.
    pub exec_path: String,
    /// Base vaddr of the anonymous heap region.
    pub heap_base: u64,
    /// First address past the anonymous heap region.
    pub heap_end: u64,
    /// The ptmalloc arenas the fixture embeds.
    pub arenas: Vec<ManifestArena>,
    /// Carved heap objects, in address order.
    pub objects: Vec<ManifestObject>,
    /// Root slots (stack words + registers holding heap pointers).
    pub roots: Vec<ManifestRoot>,
    /// Pointer edges expected to be recovered from the heap.
    pub edges: Vec<ManifestEdge>,
}

impl Manifest {
    /// Renders the manifest as indented JSON.
    pub fn to_json(&self) -> std::result::Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}
