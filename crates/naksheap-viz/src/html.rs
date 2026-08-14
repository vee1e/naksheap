//! HTML report rendering: the graph JSON is embedded in the file, while
//! cytoscape.js is loaded from a CDN at view time (network fetch required).

use std::collections::HashSet;

use naksheap_inference::{graph_to_json, Node, ObjectGraph, ObjectLabel};
use serde_json::{json, Value};

/// Renders `graph` as a single HTML file. The graph is embedded as a JSON blob
/// (with `</` escaped so it is safe inside a `<script>` tag) and drawn with
/// cytoscape.js loaded from a CDN. The HTML itself is not self-contained: it
/// needs a network fetch of `https://unpkg.com/cytoscape/...` to render. All
/// dump-derived data stays in the file / on the machine; the CDN request is the
/// only external fetch.
pub fn to_html(graph: &ObjectGraph) -> String {
    let data = json!({
        "elements": build_elements(graph),
        "graph": graph_to_json(graph),
    });
    let blob = data.to_string().replace("</", "<\\/");

    let template = r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>naksheap object graph</title>
<!-- offline: data stays local; only the cytoscape.js CDN fetch is external -->
<script src="https://unpkg.com/cytoscape/dist/cytoscape.min.js"></script>
<style>
  body { font-family: monospace; margin: 0; background: #fafafa; color: #222; }
  h1 { font-size: 18px; margin: 0; padding: 12px 16px 4px; }
  #stats { font-size: 13px; padding: 0 16px 8px; color: #444; }
  #legend { font-size: 12px; padding: 0 16px 8px; }
  #legend span { margin-right: 14px; }
  .swatch { display: inline-block; width: 11px; height: 11px; margin-right: 4px; border: 1px solid #bbb; vertical-align: -1px; }
  #cy { position: fixed; top: 92px; left: 0; right: 0; bottom: 0; }
</style>
</head>
<body>
<h1>naksheap object graph</h1>
<div id="stats">loading&hellip;</div>
<div id="legend">
  <span><span class="swatch" style="background:#2e7d32"></span>root</span>
  <span><span class="swatch" style="background:#1e88e5"></span>allocated</span>
  <span><span class="swatch" style="background:#9e9e9e"></span>freed</span>
  <span><span class="swatch" style="background:#ef6c00"></span>not root-reachable</span>
</div>
<div id="cy"></div>
<script>
const DATA = __DATA__;
(function () {
  const s = DATA.graph.stats;
  const el = document.getElementById('stats');
  el.textContent = 'objects: ' + s.total_objects
    + ' | allocated: ' + s.allocated
    + ' | freed: ' + s.freed
    + ' | root-reachable: ' + s.root_reachable
    + ' | edges: ' + s.edges
    + ' (confirmed: ' + s.confirmed_edges + ')'
    + ' | max depth: ' + s.max_depth;

  const cy = cytoscape({
    container: document.getElementById('cy'),
    elements: DATA.elements,
    style: [
      { selector: 'node', style: {
          'label': 'data(label)',
          'background-color': 'data(color)',
          'text-valign': 'center',
          'text-halign': 'center',
          'font-family': 'monospace',
          'font-size': 10,
          'width': 'data(w)',
          'height': 34,
          'border-width': 1,
          'border-color': '#555'
      } },
      { selector: 'edge', style: {
          'label': 'data(label)',
          'width': 'data(width)',
          'font-family': 'monospace',
          'font-size': 8,
          'curve-style': 'bezier',
          'target-arrow-shape': 'triangle',
          'arrow-scale': 0.8
      } }
    ],
    layout: { name: 'cose', animate: false, nodeRepulsion: 9000, idealEdgeLength: 110, padding: 30 }
  });
})();
</script>
</body>
</html>
"#;

    template.replace("__DATA__", &blob)
}

/// Builds the cytoscape `elements` array (nodes + object edges) from the graph.
fn build_elements(graph: &ObjectGraph) -> Vec<Value> {
    let mut elements: Vec<Value> = Vec::new();
    let node_addrs: HashSet<u64> = graph.nodes.iter().map(|n| n.addr).collect();

    for n in &graph.nodes {
        let id = format!("0x{:x}", n.addr);
        let color = node_color(n);
        let state = if n.is_root {
            "root"
        } else if !n.reachable_from_root {
            "unreachable"
        } else if n.ty.label == ObjectLabel::FreedChunk {
            "freed"
        } else {
            "allocated"
        };
        elements.push(json!({
            "data": {
                "id": id,
                "label": format!("0x{:x}\n{} [conf {:.2}]", n.addr, n.ty.name, n.ty.confidence),
                "color": color,
                "state": state,
                "w": size_bounded(n.size),
            }
        }));
    }

    let mut edge_idx = 0usize;
    for e in &graph.edges {
        if e.from == 0 || !node_addrs.contains(&e.from) || !node_addrs.contains(&e.to) {
            continue;
        }
        elements.push(json!({
            "data": {
                "id": format!("e{edge_idx}"),
                "source": format!("0x{:x}", e.from),
                "target": format!("0x{:x}", e.to),
                "label": format!("0x{:x}", e.offset),
                "width": if e.confirmed { 2.5 } else { 1.0 },
            }
        }));
        edge_idx += 1;
    }

    elements
}

fn node_color(n: &Node) -> &'static str {
    if n.is_root {
        "#2e7d32"
    } else if !n.reachable_from_root {
        "#ef6c00"
    } else if n.ty.label == ObjectLabel::FreedChunk {
        "#9e9e9e"
    } else {
        "#1e88e5"
    }
}

fn size_bounded(size: u64) -> u64 {
    size.clamp(16, 256)
}
