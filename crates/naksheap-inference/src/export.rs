//! JSON export of the object graph.

use serde_json::{json, Value};

use crate::graph::ObjectGraph;

/// Renders an [`ObjectGraph`] as a JSON value.
///
/// Top-level keys: `version`, `stats`, `arenas`, `nodes`, `edges`, `roots`.
pub fn graph_to_json(graph: &ObjectGraph) -> Value {
    json!({
        "version": format!("naksheap-inference/{}", env!("CARGO_PKG_VERSION")),
        "stats": graph.stats,
        "arenas": graph.arenas,
        "nodes": graph.nodes,
        "edges": graph.edges,
        "roots": graph.roots,
    })
}

/// Renders an [`ObjectGraph`] as pretty-printed JSON. Falls back to compact
/// JSON rather than panicking if serialization ever fails.
pub fn graph_to_json_pretty(graph: &ObjectGraph) -> String {
    serde_json::to_string_pretty(&graph_to_json(graph))
        .unwrap_or_else(|_| serde_json::to_string(&graph_to_json(graph)).unwrap_or_default())
}
