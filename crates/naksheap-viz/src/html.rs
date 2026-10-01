//! HTML report rendering.
//!
//! The graph JSON is embedded in the file and drawn by a small self-contained
//! force-directed layout written in vanilla JS on a `<canvas>`. There is no
//! external script, font, or stylesheet, so a report opens correctly from a
//! local file, over `file://`, on an air-gapped host, and years from now.
//!
//! The previous implementation delegated drawing to cytoscape.js loaded from a
//! CDN at view time. That made every report require a network fetch, which
//! broke the "analysis is fully offline" guarantee in the README and would
//! have meant a dump-derived page phoning home to a third party.

use std::collections::HashSet;

use naksheap_inference::{graph_to_json, ObjectGraph, ObjectLabel};
use serde_json::{json, Value};

/// Renders `graph` as a single self-contained HTML file.
///
/// The output has no external references of any kind: the graph data is
/// embedded as a JSON blob (with `</` escaped so it is safe inside a
/// `<script>` tag) and the renderer is inline.
pub fn to_html(graph: &ObjectGraph) -> String {
    let data = json!({
        "elements": build_elements(graph),
        "graph": graph_to_json(graph),
    });
    let blob = data.to_string().replace("</", "<\\/");

    // JS first, then the data. The reverse order would inject a fresh
    // `__DATA__` into the script (the JS reads `const DATA = __DATA__;`) and
    // leave it unsubstituted.
    TEMPLATE.replace("__JS__", JS).replace("__DATA__", &blob)
}

/// Black-and-white node rendering. Every visual distinction is carried by
/// fill style, dash pattern, or weight rather than hue, so the report stays
/// legible in monochrome and for readers who cannot rely on colour.
const JS: &str = r#"
const DATA = __DATA__;
const NODES = DATA.elements.filter(function (e) { return e.kind === 'node'; });
const EDGES = DATA.elements.filter(function (e) { return e.kind === 'edge'; });

// ---------------------------------------------------------------- layout
// Fruchterman-Reingold, run incrementally so the browser stays responsive.
const W = 90, H = 90, ITER = 300;
let pos, vel, bounds;

function init() {
  const n = NODES.length;
  pos = new Float64Array(n * 2);
  vel = new Float64Array(n * 2);
  bounds = { w: 0, h: 0 };
  // Deterministic pseudo-random seeding: same graph renders the same way, so
  // a report can be compared against a previous one.
  let seed = 12345;
  const rnd = function () {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  const golden = Math.PI * (3 - Math.sqrt(5));
  for (let i = 0; i < n; i++) {
    const r = 10 + 180 * Math.sqrt((i + 0.5) / n);
    pos[i * 2] = Math.cos(i * golden) * r;
    pos[i * 2 + 1] = Math.sin(i * golden) * r;
  }
  const idx = {};
  for (let i = 0; i < n; i++) idx[NODES[i].id] = i;
  edges = [];
  for (let i = 0; i < EDGES.length; i++) {
    const s = idx[EDGES[i].source], t = idx[EDGES[i].target];
    if (s !== undefined && t !== undefined) edges.push([s, t]);
  }
}

function step() {
  const n = NODES.length;
  const area = W * H, k = Math.sqrt(area / n);
  let dx = new Float64Array(n), dy = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      let ex = pos[i * 2] - pos[j * 2];
      let ey = pos[i * 2 + 1] - pos[j * 2 + 1];
      let d = Math.sqrt(ex * ex + ey * ey) || 0.01;
      // Repulsion falls off with distance; cap it so a tight cluster does not
      // fling nodes off screen.
      let f = Math.min((k * k) / d, 2000);
      ex = (ex / d) * f; ey = (ey / d) * f;
      dx[i] += ex; dy[i] += ey;
      dx[j] -= ex; dy[j] -= ey;
    }
  }
  for (let i = 0; i < edges.length; i++) {
    const s = edges[i][0], t = edges[i][1];
    let ex = pos[s * 2] - pos[t * 2];
    let ey = pos[s * 2 + 1] - pos[t * 2 + 1];
    let d = Math.sqrt(ex * ex + ey * ey) || 0.01;
    let f = (d * d) / k;
    ex = (ex / d) * f; ey = (ey / d) * f;
    dx[s] -= ex; dy[s] -= ey;
    dx[t] += ex; dy[t] += ey;
  }
  for (let i = 0; i < n; i++) {
    // Weak gravity keeps disconnected components from drifting to infinity.
    dx[i] -= pos[i * 2] * 0.02;
    dy[i] -= pos[i * 2 + 1] * 0.02;
    let d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 0.01;
    let lim = d / (2 * Math.max(d, 0.05 * k));
    vel[i * 2] = (vel[i * 2] + (dx[i] / d) * lim) * 0.85;
    vel[i * 2 + 1] = (vel[i * 2 + 1] + (dy[i] / d) * lim) * 0.85;
    pos[i * 2] += vel[i * 2];
    pos[i * 2 + 1] += vel[i * 2 + 1];
  }
  // Track the drawn extent for fit-to-view.
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  for (let i = 0; i < n; i++) {
    if (pos[i * 2] < minX) minX = pos[i * 2];
    if (pos[i * 2] > maxX) maxX = pos[i * 2];
    if (pos[i * 2 + 1] < minY) minY = pos[i * 2 + 1];
    if (pos[i * 2 + 1] > maxY) maxY = pos[i * 2 + 1];
  }
  bounds = { minX: minX, maxX: maxX, minY: minY, maxY: maxY };
}

// ------------------------------------------------------------------ view
const cv = document.getElementById('cv');
const ctx = cv.getContext('2d');
let scale = 1, panX = 0, panY = 0, sel = -1, hover = -1, iter = 0;

function resize() {
  const dpr = window.devicePixelRatio || 1;
  cv.width = cv.clientWidth * dpr;
  cv.height = cv.clientHeight * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
}
window.addEventListener('resize', resize);

function fit() {
  const w = cv.clientWidth, h = cv.clientHeight;
  const bw = Math.max(bounds.maxX - bounds.minX, 1);
  const bh = Math.max(bounds.maxY - bounds.minY, 1);
  scale = Math.min(w / (bw + 120), h / (bh + 120)) * 0.9;
  panX = w / 2 - ((bounds.minX + bounds.maxX) / 2) * scale;
  panY = h / 2 - ((bounds.minY + bounds.maxY) / 2) * scale;
}

function sx(i) { return pos[i * 2] * scale + panX; }
function sy(i) { return pos[i * 2 + 1] * scale + panY; }

function nodeStyle(nd) {
  if (nd.state === 'root') return { fill: '#111', stroke: '#111', dash: [], w: 2.5 };
  if (nd.state === 'unreachable') return { fill: '#fff', stroke: '#111', dash: [3, 2], w: 2 };
  if (nd.state === 'freed') return { fill: '#fff', stroke: '#999', dash: [2, 2], w: 1 };
  return { fill: '#fff', stroke: '#111', dash: [], w: 2 };
}

// `w` is the object size clamped to 16..256 by the Rust side. Map that band
// onto a visible radius range, otherwise every node clamps to the same
// maximum and size conveys nothing.
function radius(nd) { return 4 + (nd.w - 16) / 240 * 20; }

function draw() {
  const w = cv.clientWidth, h = cv.clientHeight;
  ctx.clearRect(0, 0, w, h);
  ctx.fillStyle = '#fff';
  ctx.fillRect(0, 0, w, h);
  ctx.save();
  for (let i = 0; i < edges.length; i++) {
    const s = edges[i][0], t = edges[i][1];
    const conf = EDGES[i] && EDGES[i].confirmed;
    ctx.strokeStyle = conf ? '#111' : '#bbb';
    ctx.lineWidth = conf ? 1.6 : 1;
    ctx.setLineDash(conf ? [] : [3, 3]);
    ctx.beginPath();
    ctx.moveTo(sx(s), sy(s));
    ctx.lineTo(sx(t), sy(t));
    ctx.stroke();
  }
  ctx.setLineDash([]);
  ctx.font = '10px ui-monospace, SFMono-Regular, Menlo, monospace';
  ctx.textAlign = 'center';
  for (let i = 0; i < NODES.length; i++) {
    const nd = NODES[i], st = nodeStyle(nd);
    const x = sx(i), y = sy(i), r = radius(nd);
    ctx.beginPath();
    ctx.arc(x, y, r, 0, Math.PI * 2);
    ctx.fillStyle = st.fill;
    ctx.fill();
    ctx.strokeStyle = st.stroke;
    ctx.lineWidth = st.w;
    ctx.setLineDash(st.dash);
    ctx.stroke();
    ctx.setLineDash([]);
    if (i === sel || i === hover) {
      ctx.beginPath();
      ctx.arc(x, y, r + 3, 0, Math.PI * 2);
      ctx.strokeStyle = '#111';
      ctx.setLineDash([2, 2]);
      ctx.lineWidth = 1;
      ctx.stroke();
      ctx.setLineDash([]);
    }
    if (scale > 0.55) {
      ctx.fillStyle = i === sel ? '#111' : '#333';
      ctx.fillText('0x' + nd.addr.toString(16), x, y + r + 11);
    }
  }
  ctx.restore();
  drawDetail();
}

function drawDetail() {
  const box = document.getElementById('detail');
  if (sel < 0) { box.textContent = 'click a node for detail'; return; }
  const nd = NODES[sel];
  const g = DATA.graph.nodes.filter(function (n) { return Number(n.addr) === nd.addr; })[0];
  if (!g) { box.textContent = ''; return; }
  const lines = [];
  lines.push('0x' + g.addr.toString(16) + '  size ' + g.size + '  ' + g.state);
  lines.push('type  ' + g.ty.name + '  confidence ' + g.ty.confidence.toFixed(2));
  if (g.ty.evidence && g.ty.evidence.length) {
    lines.push('evidence');
    for (const e of g.ty.evidence) lines.push('  ' + e);
  }
  if (g.ty.fields && g.ty.fields.length) {
    lines.push('fields');
    for (const f of g.ty.fields) {
      lines.push('  +0x' + Number(f.offset).toString(16) + '  ' + f.name + '  ' + f.kind);
    }
  }
  lines.push('inbound ' + g.inbound + '  outbound ' + g.outbound
    + '  reachable ' + g.reachable_from_root);
  box.textContent = lines.join('\n');
}

function pick(px, py) {
  let best = -1, bestD = 1e9;
  for (let i = 0; i < NODES.length; i++) {
    // Hit target is a little larger than the drawn radius so small nodes stay
    // clickable.
    const r = radius(NODES[i]) + 4;
    const d = (px - sx(i)) * (px - sx(i)) + (py - sy(i)) * (py - sy(i));
    if (d < r * r && d < bestD) { bestD = d; best = i; }
  }
  return best;
}

let dragging = false, lastX = 0, lastY = 0, moved = false;
cv.addEventListener('mousedown', function (e) { dragging = true; moved = false; lastX = e.clientX; lastY = e.clientY; });
window.addEventListener('mouseup', function (e) {
  if (dragging && !moved) {
    const rect = cv.getBoundingClientRect();
    sel = pick(e.clientX - rect.left, e.clientY - rect.top);
    draw();
  }
  dragging = false;
});
window.addEventListener('mousemove', function (e) {
  if (dragging) {
    panX += e.clientX - lastX;
    panY += e.clientY - lastY;
    lastX = e.clientX; lastY = e.clientY;
    moved = moved || Math.abs(e.movementX) + Math.abs(e.movementY) > 2;
    draw();
  } else {
    const rect = cv.getBoundingClientRect();
    const h = pick(e.clientX - rect.left, e.clientY - rect.top);
    if (h !== hover) { hover = h; cv.style.cursor = h >= 0 ? 'pointer' : 'default'; draw(); }
  }
});
cv.addEventListener('wheel', function (e) {
  e.preventDefault();
  const rect = cv.getBoundingClientRect();
  const mx = e.clientX - rect.left, my = e.clientY - rect.top;
  const f = e.deltaY < 0 ? 1.12 : 1 / 1.12;
  const ns = Math.max(0.05, Math.min(40, scale * f));
  panX = mx - (mx - panX) * (ns / scale);
  panY = my - (my - panY) * (ns / scale);
  scale = ns;
  draw();
}, { passive: false });

document.getElementById('fit').addEventListener('click', function () { fit(); draw(); });
document.getElementById('reset').addEventListener('click', function () {
  init(); fit(); draw();
});

// ------------------------------------------------------------------ start
(function () {
  const s = DATA.graph.stats;
  document.getElementById('stats').textContent =
    'objects ' + s.total_objects
    + ' | allocated ' + s.allocated
    + ' | freed ' + s.freed
    + ' | root-reachable ' + s.root_reachable
    + ' | edges ' + s.edges
    + ' (' + s.confirmed_edges + ' confirmed)'
    + ' | max depth ' + s.max_depth;
  init();
  resize();
  // Run the layout in slices so the page paints immediately and stays
  // responsive; a large graph would otherwise freeze the tab.
  function run() {
    const slice = Math.max(1, Math.floor(ITER / 30));
    for (let s = 0; s < slice && iter < ITER; s++, iter++) step();
    draw();
    if (iter < ITER) {
      requestAnimationFrame(run);
    } else {
      // Fit only once the layout has settled. Fitting early fits to a
      // collapsed graph, and the real layout then expands past the viewport.
      fit();
      draw();
    }
  }
  requestAnimationFrame(run);
})();
"#;

const TEMPLATE: &str = r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>naksheap object graph</title>
<!-- Self-contained: no external script, font, or stylesheet. -->
<style>
  :root { --ink: #111; --paper: #fff; --faint: #999; --rule: #d5d5d5; }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--paper); color: var(--ink);
    font: 13px/1.5 ui-monospace, SFMono-Regular, Menlo, monospace;
  }
  header { padding: 14px 16px 8px; border-bottom: 1px solid var(--rule); }
  h1 { font-size: 15px; font-weight: 600; margin: 0 0 6px; letter-spacing: -0.01em; }
  #stats { color: #333; }
  .bar { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; margin-top: 8px; }
  .legend { display: flex; gap: 14px; flex-wrap: wrap; font-size: 12px; color: #333; }
  .legend span { display: inline-flex; align-items: center; gap: 5px; }
  .sw { width: 11px; height: 11px; border-radius: 50%; border: 2px solid var(--ink); background: var(--paper); }
  .sw.root { background: var(--ink); }
  .sw.unreach { border-style: dashed; }
  .sw.freed { border-color: var(--faint); border-style: dashed; }
  button {
    font: inherit; padding: 3px 10px; background: var(--paper); color: var(--ink);
    border: 1px solid var(--ink); cursor: pointer; border-radius: 2px;
  }
  button:hover { background: var(--ink); color: var(--paper); }
  #main { display: flex; height: calc(100vh - 118px); }
  #cv { flex: 1 1 auto; display: block; min-width: 0; }
  #detail {
    flex: 0 0 340px; border-left: 1px solid var(--rule); padding: 12px 14px;
    white-space: pre-wrap; overflow: auto; font-size: 12px; color: #222;
  }
  @media (max-width: 720px) {
    #main { flex-direction: column; height: auto; }
    #cv { height: 60vh; }
    #detail { flex: none; border-left: none; border-top: 1px solid var(--rule); }
  }
</style>
</head>
<body>
<header>
  <h1>naksheap object graph</h1>
  <div id="stats">loading&hellip;</div>
  <div class="bar">
    <div class="legend">
      <span><span class="sw root"></span>root</span>
      <span><span class="sw"></span>allocated</span>
      <span><span class="sw freed"></span>freed</span>
      <span><span class="sw unreach"></span>unreachable</span>
    </div>
    <button id="fit">fit</button>
    <button id="reset">replay</button>
  </div>
</header>
<div id="main">
  <canvas id="cv"></canvas>
  <pre id="detail">click a node for detail</pre>
</div>
<script>
__JS__
</script>
</body>
</html>
"##;

/// Builds the renderer's element list (nodes + object edges) from the graph.
fn build_elements(graph: &ObjectGraph) -> Vec<Value> {
    let mut elements: Vec<Value> = Vec::new();
    let node_addrs: HashSet<u64> = graph.nodes.iter().map(|n| n.addr).collect();

    for n in &graph.nodes {
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
            "kind": "node",
            "id": format!("0x{:x}", n.addr),
            "addr": n.addr,
            "label": n.ty.name,
            "state": state,
            "w": size_bounded(n.size),
        }));
    }

    for e in &graph.edges {
        if e.from == 0 || !node_addrs.contains(&e.from) || !node_addrs.contains(&e.to) {
            continue;
        }
        elements.push(json!({
            "kind": "edge",
            "source": format!("0x{:x}", e.from),
            "target": format!("0x{:x}", e.to),
            "offset": format!("0x{:x}", e.offset),
            "confirmed": e.confirmed,
        }));
    }

    elements
}

fn size_bounded(size: u64) -> u64 {
    size.clamp(16, 256)
}
