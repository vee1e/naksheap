//! The naksheap output model: per-object inferred types, confidence scores,
//! reference edges, and graph-level statistics.

use serde::Serialize;

/// Semantic kind of an inferred field inside a typed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// A word that points into a carved heap object (or another mapped range).
    Pointer,
    /// A word that points into file-backed (rodata-like) memory: a vtable.
    Vtable,
    /// An inline or pointed-to ASCII/UTF-8 string.
    String,
    /// A numeric value (length, capacity, counter, ...).
    Integer,
    /// A byte blob.
    Bytes,
}

/// One inferred field inside a typed object.
#[derive(Debug, Clone, Serialize)]
pub struct Field {
    /// Byte offset of the field inside the object's user region.
    pub offset: u64,
    pub kind: FieldKind,
    /// Human-readable target description (e.g. `-> 0x7faa00002f00`).
    pub hint: Option<String>,
}

/// The inferred type of a single object.
#[derive(Debug, Clone, Serialize)]
pub struct ObjectType {
    /// Display name, e.g. "probable struct", "likely std::string".
    pub name: String,
    pub label: ObjectLabel,
    /// 0.0..=1.0, rounded to two decimals.
    pub confidence: f64,
    /// Human-readable evidence lines (addresses, sizes, counts).
    pub evidence: Vec<String>,
    /// Object size in bytes.
    pub size: u64,
    /// Number of instances in the same layout cluster.
    pub members: usize,
    /// Inferred fields (empty for scalar / untyped objects).
    pub fields: Vec<Field>,
}

/// Coarse classification label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectLabel {
    ProbableStruct,
    StdString,
    Vector,
    VtableObject,
    OpaqueBuffer,
    ZeroRegion,
    FreedChunk,
}

/// A node in the object reference graph: one carved heap object plus its
/// inferred type and graph position.
#[derive(Debug, Clone, Serialize)]
pub struct Node {
    pub addr: u64,
    pub size: u64,
    pub state: naksheap_allocator_heuristics::ObjectState,
    pub ty: ObjectType,
    /// Number of Object-source edges pointing here.
    pub inbound: usize,
    pub outbound: usize,
    pub reachable_from_root: bool,
    /// True when a register/stack root references this object.
    pub is_root: bool,
}

/// Graph-wide aggregate statistics.
#[derive(Debug, Clone, Serialize)]
pub struct GraphStats {
    pub total_objects: usize,
    pub allocated: usize,
    pub freed: usize,
    pub mmap: usize,
    /// Number of distinct ProbableStruct layout clusters (>= 2 members).
    pub clusters: usize,
    pub root_reachable: usize,
    pub edges: usize,
    pub confirmed_edges: usize,
    /// BFS depth from roots over object edges.
    pub max_depth: usize,
}

/// One reference edge in the object graph.
#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub from: u64,
    pub to: u64,
    pub offset: u64,
    pub confirmed: bool,
    pub source: naksheap_pointer_scan::EdgeSource,
}
