//! Graphviz DOT rendering of the object graph.

use std::collections::HashSet;

use naksheap_inference::{Node, ObjectGraph, ObjectLabel};

/// Renders `graph` as a Graphviz DOT digraph. Nodes are colored by state
/// (root green, unreachable orange, freed gray, allocated lightblue); edges
/// carry the pointer offset and are drawn thick when confirmed.
pub fn to_dot(graph: &ObjectGraph) -> String {
    let mut out = String::new();
    out.push_str("digraph naksheap {\n");
    out.push_str("  graph [fontname=\"monospace\"];\n");
    out.push_str("  node [fontname=\"monospace\" shape=\"box\"];\n");
    out.push_str("  edge [fontname=\"monospace\"];\n");

    let node_addrs: HashSet<u64> = graph.nodes.iter().map(|n| n.addr).collect();

    for n in &graph.nodes {
        let color = node_color(n);
        let name = dot_escape(&n.ty.name);
        out.push_str(&format!(
            "  \"0x{:x}\" [label=\"0x{:x}\\n{} [conf {:.2}]\" color=\"{}\" fillcolor=\"{}\" style=\"filled\"];\n",
            n.addr, n.addr, name, n.ty.confidence, color, color
        ));
    }

    for e in &graph.edges {
        if e.from == 0 || !node_addrs.contains(&e.from) || !node_addrs.contains(&e.to) {
            continue;
        }
        let penwidth = if e.confirmed { 2 } else { 1 };
        out.push_str(&format!(
            "  \"0x{:x}\" -> \"0x{:x}\" [label=\"0x{:x}\" penwidth={}];\n",
            e.from, e.to, e.offset, penwidth
        ));
    }

    out.push_str("}\n");
    out
}

fn node_color(n: &Node) -> &'static str {
    if n.is_root {
        "green"
    } else if !n.reachable_from_root {
        "orange"
    } else if n.ty.label == ObjectLabel::FreedChunk {
        "gray"
    } else {
        "lightblue"
    }
}

fn dot_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
