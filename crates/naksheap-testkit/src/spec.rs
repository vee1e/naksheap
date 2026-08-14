//! Fixture specification types.
//!
//! A [`CoreSpec`] is a declarative description of a synthetic 64-bit Linux
//! glibc core dump. [`CoreSpec::build`](crate::CoreSpec::build) turns it into
//! a [`Fixture`](crate::Fixture): deterministic ELF64 bytes plus a
//! ground-truth [`Manifest`](crate::Manifest).

use serde::{Deserialize, Serialize};

/// Where a pointer word should point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// The heap object carrying this label. Resolved to its user address at
    /// build time; the label must exist in [`CoreSpec::objects`].
    Label(String),
    /// An arbitrary absolute address (e.g. a fake vtable or string literal in
    /// the read-only rodata region).
    Absolute(u64),
}

/// A pointer stored inside a spec object's user region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerField {
    /// Byte offset of the word inside the object's user region.
    pub offset: usize,
    /// What the word points at.
    pub target: Target,
}

/// Allocator state requested for a spec object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum SpecState {
    /// Live chunk (`PREV_INUSE` set on the successor).
    #[default]
    Allocated,
    /// Freed chunk (`PREV_INUSE` cleared on the successor).
    Freed,
}


/// A single heap object to materialize as a glibc ptmalloc chunk.
///
/// The requested `size` is the *user* region size; the builder rounds the
/// chunk footprint up to 16 bytes (`(0x10 + size + 0xf) & !0xf`), so the
/// carved usable size recorded in the manifest may exceed `size`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecObject {
    /// Semantic label; must be unique across the spec and is what pointer
    /// fields and the manifest use to name the object.
    pub label: String,
    /// Requested user-region size in bytes. Must be at least `0x10`.
    pub size: usize,
    /// Allocator state of the chunk.
    #[serde(default)]
    pub state: SpecState,
    /// Pointer words to embed in the user region (must fit within `size`).
    #[serde(default)]
    pub pointers: Vec<PointerField>,
    /// Byte used to fill the user region; keeps output byte-for-byte
    /// deterministic without relying on randomness.
    #[serde(default = "default_fill")]
    pub fill: u8,
}

fn default_fill() -> u8 {
    0x41
}

impl SpecObject {
    /// Convenience constructor for an allocated object with a fill pattern.
    pub fn new(label: impl Into<String>, size: usize) -> Self {
        SpecObject {
            label: label.into(),
            size,
            state: SpecState::Allocated,
            pointers: Vec::new(),
            fill: 0x41,
        }
    }

    /// Adds a heap-edge pointer to `target_label` at `offset`.
    pub fn ptr(mut self, offset: usize, target_label: impl Into<String>) -> Self {
        self.pointers.push(PointerField {
            offset,
            target: Target::Label(target_label.into()),
        });
        self
    }

    /// Adds a pointer to an absolute address (rodata/vtable edge).
    pub fn ptr_abs(mut self, offset: usize, address: u64) -> Self {
        self.pointers.push(PointerField {
            offset,
            target: Target::Absolute(address),
        });
        self
    }

    /// Marks the chunk as freed.
    pub fn freed(mut self) -> Self {
        self.state = SpecState::Freed;
        self
    }
}

/// A root slot: a pointer-sized word placed in the stack blob at `address`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecRoot {
    /// Absolute stack address of the slot. Must lie inside the stack region.
    pub address: u64,
    /// What the word points at.
    pub target: Target,
}

/// Full description of one synthetic core fixture.
///
/// The default value is a realistic, self-consistent fixture: a `linked_list`
/// ring of three nodes with a stack root, a `payload` buffer with a rodata
/// pointer, and a `freed_slot` — all governed by a `main_arena` embedded in a
/// fake `libc` data blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreSpec {
    /// Process name (`pr_fname`, truncated to 16 bytes at build time).
    pub process_name: String,
    /// Command line (`pr_psargs`, truncated to 80 bytes at build time).
    pub command_line: String,
    /// Main executable path (first non-library `NT_FILE` entry).
    pub exec_path: String,
    /// `pid` embedded in `NT_PRSTATUS`.
    pub pid: i32,
    /// vaddr of the fake executable text segment (`r-x`, `ET_CORE` main image).
    pub text_base: u64,
    /// vaddr of the fake libc data segment (`rw-`, file-backed) that holds the
    /// `main_arena` at `libc_base + 0x1000`.
    pub libc_base: u64,
    /// vaddr of the anonymous `rw-` heap segment holding the chunk chain.
    pub heap_base: u64,
    /// Size of the anonymous heap segment.
    pub heap_size: u64,
    /// vaddr of the anonymous `rw-` stack segment.
    pub stack_base: u64,
    /// Size of the anonymous stack segment.
    pub stack_size: u64,
    /// Heap objects to materialize, in address order.
    pub objects: Vec<SpecObject>,
    /// Pointer words to embed near the top of the stack blob.
    pub roots: Vec<SpecRoot>,
}

impl Default for CoreSpec {
    fn default() -> Self {
        CoreSpec {
            process_name: "toy-server".to_string(),
            command_line: "./toy-server --listen :8080 --workers 4".to_string(),
            exec_path: "/opt/app/toy-server".to_string(),
            pid: 4242,
            text_base: 0x400000,
            libc_base: 0x7faa_0000_0000,
            heap_base: 0x7f00_0000_0000,
            heap_size: 0x4000,
            stack_base: 0x7fff_0000_0000,
            stack_size: 0x4000,
            objects: vec![
                // Linked-list ring (head -> second -> tail -> head): exercises
                // cycle detection in the pointer scan.
                SpecObject::new("head", 0x20).ptr(0, "second"),
                SpecObject::new("second", 0x20).ptr(0, "tail"),
                SpecObject::new("tail", 0x20).ptr(0, "head"),
                // Buffer holding a heap pointer plus a fake vtable in the
                // read-only rodata region.
                SpecObject::new("payload", 0x40)
                    .ptr(0, "head")
                    .ptr_abs(8, 0x7faa_0000_4080),
                // Freed chunk: PREV_INUSE cleared on its successor.
                SpecObject::new("freed_slot", 0x20).freed(),
            ],
            roots: vec![SpecRoot {
                address: 0x7fff_0000_3fd0,
                target: Target::Label("head".to_string()),
            }],
        }
    }
}
