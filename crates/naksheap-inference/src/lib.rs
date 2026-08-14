//! naksheap-inference
//!
//! Consumes a carved heap inventory ([`naksheap_allocator_heuristics`]) plus a
//! pointer-scan result ([`naksheap_pointer_scan`]) and produces the naksheap
//! output model: per-object inferred types (probable struct, `std::string`,
//! vector, vtable object, opaque buffer) with confidence + evidence, an object
//! reference graph, root reachability, statistics, and JSON export.
//!
//! The pipeline:
//!
//! 1. [`cluster::cluster_objects`] groups live objects by layout similarity
//!    (size + pointer/string column shapes).
//! 2. [`graph::build_graph`] infers per-object types, aggregates edges,
//!    computes root reachability and statistics.
//! 3. [`export::graph_to_json`] renders the result as JSON.

pub mod cluster;
pub mod export;
pub mod graph;
pub mod types;

pub use export::{graph_to_json, graph_to_json_pretty};
pub use graph::{build_graph, ObjectGraph};
pub use types::{Field, FieldKind, Node, ObjectLabel, ObjectType};
