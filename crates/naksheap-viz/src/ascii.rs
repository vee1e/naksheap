//! Root-anchored ASCII tree rendering of the object graph.

use std::collections::{HashMap, HashSet};

use naksheap_inference::types::GraphEdge;
use naksheap_inference::{Field, FieldKind, Node, ObjectGraph, ObjectLabel};

/// Maximum number of unreachable objects listed in the trailing section before
/// the remainder is collapsed into a count.
const MAX_UNREACHABLE_LISTED: usize = 20;

/// Renders `graph` as a root-anchored ASCII tree starting at root nodes
/// (nodes referenced by a register/stack edge); falls back to the highest
/// inbound node when no root exists. Recursion over outgoing object edges is
/// bounded by `max_depth` and guarded against cycles. A trailing section lists
/// carved objects that no root could reach, so consumers never silently miss
/// objects.
pub fn ascii_tree(graph: &ObjectGraph, max_depth: usize) -> String {
    // O(1) addr -> node lookup, replacing the per-edge linear scan.
    let node_by_addr: HashMap<u64, &Node> =
        graph.nodes.iter().map(|n| (n.addr, n)).collect();

    // Pre-index outgoing object edges by source (`from != 0`) so each node is
    // rendered in O(outgoing) instead of a full edge-list scan per node.
    let mut outgoing: HashMap<u64, Vec<&GraphEdge>> = HashMap::new();
    for e in &graph.edges {
        if e.from != 0 {
            outgoing.entry(e.from).or_default().push(e);
        }
    }

    let mut w = TreeWriter {
        outgoing: &outgoing,
        node_by_addr: &node_by_addr,
        out: Vec::new(),
        visited: HashSet::new(),
        max_depth,
    };

    let s = &graph.stats;
    w.out.push("naksheap object graph".to_string());
    w.out.push(format!(
        "objects: {} (allocated: {}, freed: {}, mmap: {}), clusters: {}, root-reachable: {}, edges: {} ({} confirmed), max depth: {}",
        s.total_objects, s.allocated, s.freed, s.mmap, s.clusters, s.root_reachable, s.edges,
        s.confirmed_edges, s.max_depth
    ));

    if graph.nodes.is_empty() {
        w.out.push("(no objects)".to_string());
        return w.out.join("\n");
    }

    for (i, node) in pick_roots(graph, &node_by_addr).iter().enumerate() {
        if i > 0 {
            w.out.push(String::new());
        }
        if w.visited.contains(&node.addr) {
            w.out.push(format!("0x{:x} (see above)", node.addr));
            continue;
        }
        w.visited.insert(node.addr);
        w.render_root(node);
    }

    let unreachable: Vec<&Node> = graph
        .nodes
        .iter()
        .filter(|n| !n.reachable_from_root && !n.is_root)
        .collect();
    if !unreachable.is_empty() {
        w.out.push(String::new());
        let total = unreachable.len();
        w.out.push(format!(
            "unreachable ({}): {} not reachable from any root",
            total,
            if total == 1 { "object" } else { "objects" }
        ));
        for n in unreachable.iter().take(MAX_UNREACHABLE_LISTED) {
            w.out.push(format!(
                "  0x{:x} {} [conf {:.2}]",
                n.addr, n.ty.name, n.ty.confidence
            ));
        }
        if total > MAX_UNREACHABLE_LISTED {
            w.out.push(format!(
                "  ... and {} more",
                total - MAX_UNREACHABLE_LISTED
            ));
        }
    }

    w.out.join("\n")
}

struct TreeWriter<'a> {
    outgoing: &'a HashMap<u64, Vec<&'a GraphEdge>>,
    node_by_addr: &'a HashMap<u64, &'a Node>,
    out: Vec<String>,
    visited: HashSet<u64>,
    max_depth: usize,
}

impl TreeWriter<'_> {
    fn render_root(&mut self, node: &Node) {
        self.out.push(format!("0x{:x}", node.addr));
        self.out.push(format!("└── {}", type_line(node)));
        self.render_children(node, "    ", 0);
    }

    fn render_node(&mut self, node: &Node, is_last: bool, prefix: &str, depth: usize) {
        let conn = if is_last { "└── " } else { "├── " };
        let spacing = if is_last { "    " } else { "│   " };
        self.out.push(format!("{prefix}{conn}0x{:x}", node.addr));
        self.out.push(format!("{prefix}{spacing}└── {}", type_line(node)));
        let child_indent = format!("{prefix}{spacing}    ");
        self.render_children(node, &child_indent, depth);
    }

    fn render_children(&mut self, node: &Node, indent: &str, depth: usize) {
        let mut items: Vec<Item> = node.ty.fields.iter().map(Item::Field).collect();
        let mut seen: HashSet<u64> = HashSet::new();
        if let Some(edges) = self.outgoing.get(&node.addr) {
            for e in edges {
                if let Some(target) = self.node_by_addr.get(&e.to).copied() {
                    if seen.insert(target.addr) {
                        items.push(Item::Node(target));
                    }
                }
            }
        }

        for (i, item) in items.iter().enumerate() {
            let last = i == items.len() - 1;
            let conn = if last { "└── " } else { "├── " };
            match item {
                Item::Field(f) => {
                    self.out.push(format!("{indent}{conn}{}", field_body(f)));
                }
                Item::Node(n) => {
                    if self.visited.contains(&n.addr) {
                        self.out.push(format!("{indent}{conn}0x{:x} (see above)", n.addr));
                    } else if depth + 1 > self.max_depth {
                        self.out.push(format!("{indent}{conn}0x{:x} (depth limit)", n.addr));
                    } else {
                        self.visited.insert(n.addr);
                        self.render_node(n, last, indent, depth + 1);
                    }
                }
            }
        }
    }
}

/// Picks the render start points: every root node, or the single highest
/// inbound node when there are no roots. Deterministic (sorted by address).
fn pick_roots<'a>(graph: &'a ObjectGraph, node_by_addr: &HashMap<u64, &'a Node>) -> Vec<&'a Node> {
    let mut addrs: Vec<u64> = graph
        .nodes
        .iter()
        .filter(|n| n.is_root)
        .map(|n| n.addr)
        .collect();
    addrs.sort_unstable();
    let roots: Vec<&'a Node> = addrs
        .iter()
        .filter_map(|a| node_by_addr.get(a).copied())
        .collect();
    if !roots.is_empty() {
        return roots;
    }
    let mut best: Option<&'a Node> = None;
    for n in &graph.nodes {
        let better = match best {
            None => true,
            Some(b) => n.inbound > b.inbound || (n.inbound == b.inbound && n.addr < b.addr),
        };
        if better {
            best = Some(n);
        }
    }
    best.into_iter().collect()
}

enum Item<'a> {
    Field(&'a Field),
    Node(&'a Node),
}

fn type_line(node: &Node) -> String {
    let mut s = format!(
        "{} [conf {:.2}, n={}]",
        node.ty.name, node.ty.confidence, node.ty.members
    );
    if node.is_root {
        s.push_str(" [root]");
    }
    if node.ty.label == ObjectLabel::FreedChunk {
        s.push_str(" [freed]");
    }
    s
}

fn field_body(f: &Field) -> String {
    let kind = kind_str(f.kind);
    let hint = f.hint.as_deref().unwrap_or("");
    let body = if hint.is_empty() {
        kind.to_string()
    } else if hint.starts_with(kind) {
        hint.to_string()
    } else {
        format!("{kind} {hint}")
    };
    format!("+0x{:02x} {body}", f.offset)
}

fn kind_str(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Pointer => "pointer",
        FieldKind::Vtable => "vtable",
        FieldKind::String => "string",
        FieldKind::Integer => "integer",
        FieldKind::Bytes => "bytes",
    }
}
