//! Object reference graph construction: per-object type inference, edges,
//! root reachability, and statistics.

use std::collections::{HashMap, HashSet, VecDeque};

use naksheap_allocator_heuristics::{ArenaInfo, HeapInventory, Object, ObjectState};
use naksheap_core_parse::{AddressSpace, RangeKind};
use naksheap_pointer_scan::{index_objects, EdgeSource, ObjectIndex, ScanResult};

use crate::cluster::{is_printable, cluster_objects, LayoutCluster};
use crate::types::{
    Field, FieldKind, GraphEdge, GraphStats, Node, ObjectLabel, ObjectType,
};

/// The complete object reference graph for a carved heap.
#[derive(Debug, Clone)]
pub struct ObjectGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<GraphEdge>,
    pub roots: Vec<naksheap_pointer_scan::Root>,
    pub stats: GraphStats,
    /// Pass-through of the inventory arenas (included so JSON export can
    /// reproduce them).
    pub arenas: Vec<ArenaInfo>,
}

/// Builds the object graph from a carved inventory and a pointer-scan result.
///
/// Never panics on malformed reads; all reads go through `Option`.
pub fn build_graph(
    image: &(dyn AddressSpace + Sync),
    inventory: &HeapInventory,
    scan: &ScanResult,
) -> ObjectGraph {
    let clusters = cluster_objects(image, &inventory.objects, &scan.edges);

    // addr -> (cluster index, member count)
    let mut cluster_of: HashMap<u64, (usize, usize)> = HashMap::new();
    for (idx, c) in clusters.iter().enumerate() {
        for &addr in &c.members {
            cluster_of.insert(addr, (idx, c.members.len()));
        }
    }

    // O(1) base-address lookups: edge targets are always carved object bases,
    // so a HashMap keyed on the base address replaces the per-edge linear scan.
    let obj_idx: HashMap<u64, usize> =
        inventory.objects.iter().enumerate().map(|(i, o)| (o.addr, i)).collect();
    // Stabbing queries (a root word may point into an object's interior).
    let obj_index = index_objects(&inventory.objects);

    // Reference bookkeeping from scan edges.
    let mut inbound: HashMap<u64, usize> = HashMap::new();
    let mut outbound: HashMap<u64, usize> = HashMap::new();
    let mut root_targets: HashSet<u64> = HashSet::new();
    for e in &scan.edges {
        match e.source {
            EdgeSource::Object => {
                *outbound.entry(e.from).or_default() += 1;
                if let Some(target) = object_at(&inventory.objects, &obj_idx, e.to) {
                    *inbound.entry(target.addr).or_default() += 1;
                }
            }
            EdgeSource::Stack | EdgeSource::Register => {
                if let Some(target) = object_at(&inventory.objects, &obj_idx, e.to) {
                    root_targets.insert(target.addr);
                }
            }
        }
    }
    // Roots may exist without a matching edge (robustness); treat them as
    // root targets too. Root values are raw words that may point into an
    // object's interior, so resolve them through the stabbing index.
    for r in &scan.roots {
        if let Some(target) = obj_index.target_at(r.value) {
            root_targets.insert(target.addr);
        }
    }

    // Build nodes.
    let mut nodes: Vec<Node> = Vec::with_capacity(inventory.objects.len());
    for obj in &inventory.objects {
        let cluster = cluster_of
            .get(&obj.addr)
            .map(|&(idx, _)| &clusters[idx]);
        let inb = inbound.get(&obj.addr).copied().unwrap_or(0);
        let outb = outbound.get(&obj.addr).copied().unwrap_or(0);
        let is_root = root_targets.contains(&obj.addr);
        let ty = infer_type(image, obj, &obj_index, cluster, inb, outb, is_root);
        nodes.push(Node {
            addr: obj.addr,
            size: obj.size,
            state: obj.state,
            ty,
            inbound: inb,
            outbound: outb,
            reachable_from_root: false,
            is_root: root_targets.contains(&obj.addr),
        });
    }

    // Adjacency over Object-source edges (directed). Freed chunks carry
    // allocator/fastbin garbage (forward/back pointers) rather than real
    // references, so edges out of a freed node are never traversed, and live
    // pointers INTO a freed chunk (a UAF hint) are not followed either. A freed
    // node can still be marked reachable when a root directly targets it (see
    // the BFS seed below), but its outgoing edges are never expanded.
    let addr_to_idx: HashMap<u64, usize> =
        nodes.iter().enumerate().map(|(i, n)| (n.addr, i)).collect();
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); nodes.len()];
    for e in &scan.edges {
        if e.source == EdgeSource::Object {
            if let (Some(&from_idx), Some(&to_idx)) =
                (addr_to_idx.get(&e.from), addr_to_idx.get(&e.to))
            {
                if nodes[from_idx].state == ObjectState::Freed
                    || nodes[to_idx].state == ObjectState::Freed
                {
                    continue;
                }
                adj[from_idx].push(to_idx);
            }
        }
    }

    // BFS from root-targeted nodes over object edges. A freed node targeted by
    // a root (dangling stack pointer) is seeded as reachable, but since freed
    // nodes contributed no adjacency entries above, their outgoing edges are
    // never expanded.
    let mut reachable = vec![false; nodes.len()];
    let mut max_depth = 0usize;
    let mut queue: VecDeque<(usize, usize)> = VecDeque::new();
    for (i, n) in nodes.iter().enumerate() {
        if n.is_root {
            reachable[i] = true;
            queue.push_back((i, 0));
        }
    }
    while let Some((u, d)) = queue.pop_front() {
        max_depth = max_depth.max(d);
        for &v in &adj[u] {
            if !reachable[v] {
                reachable[v] = true;
                queue.push_back((v, d + 1));
            }
        }
    }
    for (i, n) in nodes.iter_mut().enumerate() {
        n.reachable_from_root = reachable[i];
    }

    let edges: Vec<GraphEdge> = scan
        .edges
        .iter()
        .map(|e| GraphEdge {
            from: e.from,
            to: e.to,
            offset: e.offset,
            confirmed: e.confirmed,
            source: e.source,
        })
        .collect();

    let stats = compute_stats(&nodes, &edges, &clusters, max_depth);

    ObjectGraph {
        nodes,
        edges,
        roots: scan.roots.clone(),
        stats,
        arenas: inventory.arenas.clone(),
    }
}

fn compute_stats(
    nodes: &[Node],
    edges: &[GraphEdge],
    clusters: &[LayoutCluster],
    max_depth: usize,
) -> GraphStats {
    let total_objects = nodes.len();
    let allocated = nodes.iter().filter(|n| n.state == ObjectState::Allocated).count();
    let freed = nodes.iter().filter(|n| n.state == ObjectState::Freed).count();
    let mmap = nodes.iter().filter(|n| n.state == ObjectState::Mmap).count();
    let root_reachable = nodes.iter().filter(|n| n.reachable_from_root).count();

    // clusters = distinct ProbableStruct clusters (>= 2 members).
    let mut cluster_of: HashMap<u64, usize> = HashMap::new();
    for (idx, c) in clusters.iter().enumerate() {
        for &member in &c.members {
            cluster_of.insert(member, idx);
        }
    }
    let mut cluster_labels: HashMap<usize, ObjectLabel> = HashMap::new();
    for n in nodes {
        if let Some(&idx) = cluster_of.get(&n.addr) {
            cluster_labels.insert(idx, n.ty.label);
        }
    }
    let clusters_count = clusters
        .iter()
        .enumerate()
        .filter(|(idx, c)| {
            c.members.len() >= 2
                && cluster_labels.get(idx) == Some(&ObjectLabel::ProbableStruct)
        })
        .count();

    GraphStats {
        total_objects,
        allocated,
        freed,
        mmap,
        clusters: clusters_count,
        root_reachable,
        edges: edges.len(),
        confirmed_edges: edges.iter().filter(|e| e.confirmed).count(),
        max_depth,
    }
}

/// Returns the carved object at exactly `value` (its base address), if any.
///
/// Pointer-scan edge targets always resolve to an object's base, so an exact
/// map lookup is equivalent to the old range scan while being O(1).
fn object_at<'a>(
    objects: &'a [Object],
    base_to_idx: &HashMap<u64, usize>,
    value: u64,
) -> Option<&'a Object> {
    base_to_idx.get(&value).map(|&i| &objects[i])
}

/// Infers the type of one carved object.
/// True when every readable byte of `[addr + word, addr + size)` is zero.
/// The first word is skipped: glibc leaves a stale size word at the start of
/// abandoned top-chunk remainders (the "phantom" chunk), so we accept that
/// pattern. Bounded to the first 256 KiB so huge chunks do not stall inference.
fn content_all_zero_after_first_word(
    image: &(dyn AddressSpace + Sync),
    addr: u64,
    size: u64,
) -> bool {
    const SAMPLE: u64 = 0x40000;
    let word = image.pointer_width() as u64;
    let n = size.min(SAMPLE);
    let mut off = word;
    while off < n {
        let chunk = (n - off).min(0x1000);
        match image.read_bytes(addr.saturating_add(off), chunk) {
            Some(bytes) => {
                if bytes.iter().any(|&b| b != 0) {
                    return false;
                }
            }
            None => return false, // unreadable means not verifiably all-zero
        }
        off += chunk;
    }
    true
}

fn infer_type(
    image: &(dyn AddressSpace + Sync),
    obj: &Object,
    obj_index: &ObjectIndex,
    cluster: Option<&LayoutCluster>,
    inbound: usize,
    outbound: usize,
    is_root: bool,
) -> ObjectType {
    // (a) Allocator-verified freed chunk. The evidence names the actual
    // mechanism: PREV_INUSE-clear (bin/unsorted free), tcache free-list
    // cross-reference, or fastbin chain cross-reference.
    if obj.state == ObjectState::Freed {
        let reason = match obj.freed_reason {
            Some(naksheap_allocator_heuristics::FreedReason::Tcache) => {
                "user address found in the tcache free list".to_string()
            }
            Some(naksheap_allocator_heuristics::FreedReason::Fastbin) => {
                "user address found in an arena fastbin chain".to_string()
            }
            _ => "successor chunk has PREV_INUSE clear".to_string(),
        };
        return ObjectType {
            name: "freed chunk".to_string(),
            label: ObjectLabel::FreedChunk,
            confidence: 0.9,
            evidence: vec![
                reason,
                format!(
                    "chunk at 0x{:x} returned to allocator (size 0x{:x})",
                    obj.addr, obj.size
                ),
            ],
            size: obj.size,
            members: 0,
            fields: Vec::new(),
        };
    }

    let word = image.pointer_width() as u64;
    // For in-use glibc chunks the usable data may extend `word` bytes past the
    // reported size into the next chunk's dead `prev_size` (e.g. a 24-byte
    // std::vector stores its third word at offset 0x10 of a 0x20 chunk), so
    // typed-heuristic reads cover that spill extent. Layout clustering does NOT
    // extend (the spill is dead memory, not object data).
    let read_extent = if obj.state == ObjectState::Allocated {
        obj.size.saturating_add(word)
    } else {
        obj.size
    };
    let read = |off: u64| -> Option<u64> {
        if off.checked_add(word)? > read_extent {
            return None;
        }
        image.read_word(obj.addr.saturating_add(off))
    };

    // (a2) Large in-use chunks whose content is entirely zero are almost always
    // unused allocator reservations (e.g. the stale top-chunk remainder glibc
    // leaves after growing a heap), not live data. Flag them so they do not
    // read as mysterious "opaque buffers" in the inventory.
    // A large in-use chunk whose content is all zero after the first word is
    // usually the abandoned top-chunk remainder glibc leaves after growing a
    // heap, not live data. But a freshly-calloc'd buffer also reads all-zero,
    // so only label it when nothing references it from a register/stack root
    // (a live allocation) and keep the wording as a hypothesis.
    if obj.state == ObjectState::Allocated
        && !is_root
        && obj.size >= 0x2000
        && content_all_zero_after_first_word(image, obj.addr, obj.size)
    {
        return ObjectType {
            name: "zero-filled region (possibly unused allocator reservation)".to_string(),
            label: ObjectLabel::ZeroRegion,
            confidence: 0.5,
            evidence: vec![format!(
                "content is zero after the first word ({} bytes checked); no root reference",
                obj.size.min(0x40000)
            )],
            size: obj.size,
            members: 0,
            fields: Vec::new(),
        };
    }

    let cluster_members = cluster.map(|c| c.members.len()).unwrap_or(0);

    // (b) std::string heuristics (24..=32 byte objects: {ptr,len,cap} or SSO).
    if obj.size >= 24 && obj.size <= 32 {
        if let (Some(w0), Some(w1), Some(w2)) = (read(0), read(8), read(16)) {
            // Heap-buffer string: {data ptr, length, capacity}.
            let heapish = w0 != 0
                && image.range_at(w0).is_some_and(|r| {
                    r.perms.read && matches!(r.kind, RangeKind::Anon | RangeKind::File)
                })
                && w1 < 0x100000
                && w2 >= w1
                && w2 <= 0x1000000;
            if heapish {
                let density = string_density_at(image, w0, w1.min(16));
                if density >= 0.5 {
                    let mut evidence = vec![
                        "heap-buffer std::string layout {ptr,len,cap}".to_string(),
                        format!("ptr 0x{:x} -> heap/anon range", w0),
                        format!("length 0x{:x}, capacity 0x{:x}", w1, w2),
                        format!("bytes at 0x{:x}: {:.0}% printable", w0, density * 100.0),
                    ];
                    append_refs(&mut evidence, inbound, outbound);
                    return ObjectType {
                        name: "likely std::string".to_string(),
                        label: ObjectLabel::StdString,
                        confidence: finalize(0.85, inbound, false, Some(density)),
                        evidence,
                        size: obj.size,
                        members: cluster_members.max(1),
                        fields: vec![
                            Field {
                                offset: 0,
                                kind: FieldKind::Pointer,
                                hint: Some(format!("-> 0x{:x}", w0)),
                            },
                            Field {
                                offset: 8,
                                kind: FieldKind::Integer,
                                hint: Some(format!("length 0x{:x}", w1)),
                            },
                            Field {
                                offset: 16,
                                kind: FieldKind::Integer,
                                hint: Some(format!("capacity 0x{:x}", w2)),
                            },
                        ],
                    };
                }
            }
            // libstdc++ SSO: the capacity word has the SSO marker bit (bit 63)
            // set and the inline length lives in word1. libstdc++ stores the
            // SSO characters at offset 0, not a length word.
            let libstdcxx_sso = w2 != 0
                && (w2 & (1u64 << 63)) != 0
                && w1 < 32
                && image.read_bytes(obj.addr, w1.min(16)).is_some();
            if libstdcxx_sso {
                let density = string_density_at(image, obj.addr, w1.min(16));
                if density >= 0.5 {
                    let mut evidence = vec![
                        "libstdc++ SSO std::string: capacity word carries the SSO bit".to_string(),
                        format!("inline length 0x{:x}, capacity 0x{:x}", w1, w2),
                        format!(
                            "inline bytes at 0x{:x}: {:.0}% printable",
                            obj.addr,
                            density * 100.0
                        ),
                    ];
                    append_refs(&mut evidence, inbound, outbound);
                    return ObjectType {
                        name: "likely std::string".to_string(),
                        label: ObjectLabel::StdString,
                        confidence: finalize(0.75, inbound, false, Some(density)),
                        evidence,
                        size: obj.size,
                        members: cluster_members.max(1),
                        fields: vec![
                            Field {
                                offset: 0,
                                kind: FieldKind::Bytes,
                                hint: Some("inline string data".to_string()),
                            },
                            Field {
                                offset: 8,
                                kind: FieldKind::Integer,
                                hint: Some(format!("SSO length 0x{:x}", w1)),
                            },
                            Field {
                                offset: 16,
                                kind: FieldKind::Integer,
                                hint: Some(format!("capacity 0x{:x}", w2)),
                            },
                        ],
                    };
                }
            }
            // libc++-style SSO: word0 is a small inline length (secondary check).
            if (1..0x20).contains(&w0) && w2 >= w0 && w2 <= 0x1000000 {
                let density = string_density_at(image, obj.addr, w0.min(16));
                if density >= 0.5 {
                    let mut evidence = vec![
                        "SSO std::string: first word is inline length".to_string(),
                        format!("inline length 0x{:x}, capacity 0x{:x}", w0, w2),
                        format!(
                            "inline bytes at 0x{:x}: {:.0}% printable",
                            obj.addr,
                            density * 100.0
                        ),
                    ];
                    append_refs(&mut evidence, inbound, outbound);
                    return ObjectType {
                        name: "likely std::string".to_string(),
                        label: ObjectLabel::StdString,
                        confidence: finalize(0.75, inbound, false, Some(density)),
                        evidence,
                        size: obj.size,
                        members: cluster_members.max(1),
                        fields: vec![
                            Field {
                                offset: 0,
                                kind: FieldKind::Integer,
                                hint: Some(format!("SSO length 0x{:x}", w0)),
                            },
                            Field {
                                offset: 8,
                                kind: FieldKind::Bytes,
                                hint: Some("inline string data".to_string()),
                            },
                            Field {
                                offset: 16,
                                kind: FieldKind::Integer,
                                hint: Some(format!("capacity 0x{:x}", w2)),
                            },
                        ],
                    };
                }
            }
        }
    }

    // (c) std::vector heuristics: {begin,end,cap} with 8-byte stride, and no
    // further pointer words beyond the three leading ones. All three words must
    // land in readable mapped ranges, begin must point at real heap data, both
    // gaps must be 8-byte multiples, and the element count must be sane.
    if obj.size >= 16 {
        if let (Some(w0), Some(w1), Some(w2)) = (read(0), read(8), read(16)) {
            let count = w2.saturating_sub(w0);
            let vector_shape = w0 != 0
                && w0 <= w1
                && w1 <= w2
                && count <= 0x1000000
                && (w1 - w0) % 8 == 0
                && (w2 - w1) % 8 == 0
                && count % 8 == 0
                && count / 8 <= (1 << 20)
                && readable(image, w0)
                && readable(image, w1)
                && readable(image, w2)
                && (obj_index.target_at(w0).is_some()
                    || image.range_at(w0).is_some_and(|r| {
                        r.kind == RangeKind::Anon && r.perms.write
                    }))
                && only_three_words(image, obj, word)
                && same_allocation(image, obj_index, w0, w1, w2);
            if vector_shape {
                let mut evidence = vec![
                    "likely std::vector layout {begin,end,cap}".to_string(),
                    format!("begin 0x{:x}, end 0x{:x}, cap 0x{:x}", w0, w1, w2),
                    format!("element stride 8 ({} elements)", (w1 - w0) / 8),
                    format!("begin 0x{:x} lands in a readable mapped range", w0),
                ];
                append_refs(&mut evidence, inbound, outbound);
                return ObjectType {
                    name: "likely std::vector".to_string(),
                    label: ObjectLabel::Vector,
                    confidence: finalize(0.8, inbound, false, None),
                    evidence,
                    size: obj.size,
                    members: cluster_members.max(1),
                    fields: vec![
                        Field {
                            offset: 0,
                            kind: FieldKind::Pointer,
                            hint: Some(format!("begin -> 0x{:x}", w0)),
                        },
                        Field {
                            offset: 8,
                            kind: FieldKind::Pointer,
                            hint: Some(format!("end -> 0x{:x}", w1)),
                        },
                        Field {
                            offset: 16,
                            kind: FieldKind::Pointer,
                            hint: Some(format!("capacity -> 0x{:x}", w2)),
                        },
                    ],
                };
            }
        }
    }

    // (d) Vtable object: the first word points into a file-backed,
    // non-writable (rodata) range AND the first vtable slot itself points into
    // an executable range (a code pointer). Without the code-pointer check a
    // random rodata pointer (e.g. a string literal) would be mislabeled.
    if let Some(w0) = read(0) {
        if w0 != 0 {
            if let Some(r) = image.range_at(w0) {
                if r.kind == RangeKind::File
                    && !r.perms.write
                    && first_slot_is_code(image, w0)
                {
                    let fname = file_name(image, w0).unwrap_or_else(|| "rodata".to_string());
                    let fields = cluster
                        .map(|c| fields_from_cluster(image, obj, c))
                        .unwrap_or_default();
                    let mut evidence = vec![
                        format!("vtable -> 0x{:x} in {}", w0, fname),
                        format!(
                            "object at 0x{:x} (size 0x{:x}) leads with a rodata pointer",
                            obj.addr, obj.size
                        ),
                        format!(
                            "first vtable slot at 0x{:x} points into executable memory",
                            w0
                        ),
                    ];
                    append_refs(&mut evidence, inbound, outbound);
                    if cluster_members > 1 {
                        evidence.push(format!(
                            "{} instances share this layout",
                            cluster_members
                        ));
                    }
                    return ObjectType {
                        name: "vtable object".to_string(),
                        label: ObjectLabel::VtableObject,
                        confidence: finalize(0.8, inbound, false, None),
                        evidence,
                        size: obj.size,
                        members: cluster_members,
                        fields,
                    };
                }
            }
        }
    }

    // (e/f/g) Cluster-based classification.
    if let Some(c) = cluster {
        let fields = fields_from_cluster(image, obj, c);
        let n = c.members.len();
        let mut evidence = Vec::new();
        let (base_conf, name) = if n >= 3 {
            let conf = (0.6 + 0.06 * (n.min(5) as f64)).min(0.95);
            evidence.push(format!(
                "{} members share identical layout (size=0x{:x})",
                n, obj.size
            ));
            (conf, "probable struct".to_string())
        } else if n == 2 {
            evidence.push(format!(
                "2 instances share identical layout (size=0x{:x})",
                obj.size
            ));
            (0.5, "probable struct".to_string())
        } else {
            let conf = 0.3;
            evidence.push(format!(
                "1 instance of this layout (size=0x{:x})",
                obj.size
            ));
            (conf, "opaque buffer".to_string())
        };
        append_refs(&mut evidence, inbound, outbound);

        let vtable_hit = fields.iter().any(|f| f.kind == FieldKind::Vtable);
        if vtable_hit {
            if let Some(f) = fields.iter().find(|f| f.kind == FieldKind::Vtable) {
                evidence.push(format!(
                    "vtable-like pointer at offset 0x{:x}: {}",
                    f.offset,
                    f.hint.as_deref().unwrap_or("file-backed memory")
                ));
            }
        }

        let label = if n >= 2 {
            ObjectLabel::ProbableStruct
        } else {
            ObjectLabel::OpaqueBuffer
        };
        return ObjectType {
            name,
            label,
            confidence: finalize(base_conf, inbound, vtable_hit, None),
            evidence,
            size: obj.size,
            members: n,
            fields,
        };
    }

    // No cluster (robustness; eligible objects always land in a cluster).
    ObjectType {
        name: "opaque buffer".to_string(),
        label: ObjectLabel::OpaqueBuffer,
        confidence: 0.3,
        evidence: vec![format!("no layout cluster for object at 0x{:x}", obj.addr)],
        size: obj.size,
        members: 1,
        fields: Vec::new(),
    }
}

/// Fields from a cluster's pointer/string masks, with per-field hints.
fn fields_from_cluster(
    image: &(dyn AddressSpace + Sync),
    obj: &Object,
    c: &LayoutCluster,
) -> Vec<Field> {
    let mut fields = Vec::new();
    let n = c.pointer_mask.len().max(c.string_mask.len());
    for i in 0..n {
        let off = i as u64 * 8;
        if off >= obj.size {
            break;
        }
        if i < c.pointer_mask.len() && c.pointer_mask[i] {
            let (kind, hint) = pointer_field(image, obj.addr.saturating_add(off));
            fields.push(Field {
                offset: off,
                kind,
                hint: Some(hint),
            });
        } else if i < c.string_mask.len() && c.string_mask[i] {
            fields.push(Field {
                offset: off,
                kind: FieldKind::String,
                hint: Some("ascii string".to_string()),
            });
        }
    }
    fields
}

fn pointer_field(image: &(dyn AddressSpace + Sync), addr: u64) -> (FieldKind, String) {
    match image.read_word(addr) {
        Some(v) if v != 0 => {
            // A vtable field requires a read-only file-backed target whose first
            // slot dereferences to executable memory (a code pointer). A
            // `const char*` into rodata is a plain pointer, not a vtable.
            let rodata = image
                .range_at(v)
                .is_some_and(|r| r.kind == RangeKind::File && !r.perms.write);
            if rodata && first_slot_is_code(image, v) {
                let fname = file_name(image, v).unwrap_or_else(|| "rodata".to_string());
                (FieldKind::Vtable, format!("vtable -> 0x{:x} in {}", v, fname))
            } else {
                (FieldKind::Pointer, format!("-> 0x{:x}", v))
            }
        }
        _ => (FieldKind::Pointer, "invalid pointer".to_string()),
    }
}

/// True when the word at `addr` is itself a pointer into an executable range
/// (the first slot of a real vtable points at a function).
fn first_slot_is_code(image: &(dyn AddressSpace + Sync), addr: u64) -> bool {
    image
        .read_word(addr)
        .and_then(|v| image.range_at(v))
        .is_some_and(|r| r.perms.execute)
}

fn readable(image: &(dyn AddressSpace + Sync), v: u64) -> bool {
    image.range_at(v).is_some_and(|r| r.perms.read)
}

/// True when `w0`, `w1`, `w2` all resolve into the *same* allocation: either
/// the same carved object (`[addr, addr+size)`) or the same anonymous mapping.
///
/// A real `std::vector` owns one contiguous buffer, so its begin/end/cap all
/// fall inside a single allocation; a `{ptr, ptr, ptr}` struct typically spans
/// several objects. This gate kills the false-positive on ascending 3-pointer
/// structs whose three targets happen to be mapped and 8-byte aligned.
fn same_allocation(
    image: &(dyn AddressSpace + Sync),
    obj_index: &ObjectIndex,
    w0: u64,
    w1: u64,
    w2: u64,
) -> bool {
    if let Some(o) = obj_index.target_at(w0) {
        // A vector's `finish`/`cap` are one-past-the-end pointers, so the
        // upper bound is INCLUSIVE (`<= o.addr + o.size`).
        let end = o.addr.saturating_add(o.size);
        return w1 >= o.addr && w1 <= end && w2 >= o.addr && w2 <= end;
    }
    let r = image.range_at(w0).filter(|r| r.kind == RangeKind::Anon);
    match r {
        Some(r) => r.contains(w1) && r.contains(w2),
        None => false,
    }
}

fn file_name(image: &(dyn AddressSpace + Sync), v: u64) -> Option<String> {
    let r = image.range_at(v)?;
    if let Some(n) = &r.name {
        return Some(n.clone());
    }
    if let Some(p) = &r.path {
        return Some(p.rsplit('/').next().unwrap_or(p).to_string());
    }
    Some("file-backed range".to_string())
}

/// True when no aligned word at offset >= 24 points into mapped/file memory.
fn only_three_words(image: &(dyn AddressSpace + Sync), obj: &Object, word: u64) -> bool {
    let mut off = 24u64;
    while off.saturating_add(word) <= obj.size {
        let addr = obj.addr.saturating_add(off);
        if let Some(v) = image.read_word(addr) {
            if v != 0 {
                let mapped = image.read_bytes(v, 8).is_some();
                if mapped || image.is_file_backed(v) {
                    return false;
                }
            }
        }
        off += word;
    }
    true
}

fn string_density_at(image: &(dyn AddressSpace + Sync), addr: u64, len: u64) -> f64 {
    if len == 0 {
        return 1.0;
    }
    match image.read_bytes(addr, len) {
        Some(bytes) => {
            let good = bytes.iter().filter(|&&b| is_printable(b)).count();
            good as f64 / bytes.len() as f64
        }
        None => 0.0,
    }
}

fn append_refs(evidence: &mut Vec<String>, inbound: usize, outbound: usize) {
    if inbound > 0 {
        evidence.push(format!(
            "{} inbound reference{}",
            inbound,
            if inbound == 1 { "" } else { "s" }
        ));
    }
    if outbound > 0 {
        evidence.push(format!(
            "{} outbound reference{}",
            outbound,
            if outbound == 1 { "" } else { "s" }
        ));
    }
}

/// Combines membership confidence with reference/vtable/density bonuses,
/// clamped to [0, 1] and rounded to two decimals.
fn finalize(mut conf: f64, inbound: usize, vtable_hit: bool, density: Option<f64>) -> f64 {
    if inbound >= 2 {
        conf += 0.15;
    } else if inbound == 1 {
        conf += 0.08;
    }
    if vtable_hit {
        conf += 0.1;
    }
    if let Some(d) = density {
        if d >= 0.8 {
            conf += 0.1;
        } else if d >= 0.5 {
            conf += 0.05;
        }
    }
    conf = conf.clamp(0.0, 1.0);
    (conf * 100.0).round() / 100.0
}
