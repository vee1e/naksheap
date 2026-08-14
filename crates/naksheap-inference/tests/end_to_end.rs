//! End-to-end integration tests against the synthetic testkit fixture, plus
//! JSON export round-trip checks.

use naksheap_allocator_heuristics::ObjectState as HeurState;
use naksheap_allocator_heuristics::{HeapInventory, Object};
use naksheap_core_parse::elf::parse_elf_bytes;
use naksheap_core_parse::{MappedImage, MemoryMap, MemoryRange, Perms, RangeKind};
use naksheap_inference::{
    build_graph, graph_to_json, graph_to_json_pretty, FieldKind, ObjectGraph, ObjectLabel,
};
use naksheap_pointer_scan::{scan, Edge, EdgeSource, Root, RootSource, ScanOptions, ScanResult};
use naksheap_testkit::{CoreSpec, Manifest, ObjectState as KitState};

fn build_default() -> (ObjectGraph, Manifest) {
    let fixture = CoreSpec::default().build().expect("build fixture");
    let parsed = parse_elf_bytes(&fixture.bytes).expect("parse ELF core bytes");
    let image = MappedImage::from_bytes(
        fixture.bytes.clone(),
        parsed.map.clone(),
        parsed.pointer_width,
    );
    let inventory = naksheap_allocator_heuristics::carve(&image);
    let scan_result = scan(&image, &inventory, &parsed.threads, &ScanOptions::default());
    let graph = build_graph(&image, &inventory, &scan_result);
    (graph, fixture.manifest)
}

fn manifest_addr(manifest: &Manifest, label: &str) -> u64 {
    manifest
        .objects
        .iter()
        .find(|o| o.label == label)
        .unwrap_or_else(|| panic!("manifest has no object labelled {label}"))
        .addr
}

fn manifest_state(obj_state: KitState) -> HeurState {
    match obj_state {
        KitState::Allocated => HeurState::Allocated,
        KitState::Freed => HeurState::Freed,
        KitState::Mmap => HeurState::Mmap,
        KitState::Unknown => HeurState::Unknown,
    }
}

#[test]
fn default_fixture_end_to_end() {
    let (graph, manifest) = build_default();

    // 1. Total object count matches the manifest.
    assert_eq!(graph.stats.total_objects, manifest.objects.len());

    // 2. Every object's addr/size/state matches the manifest.
    for mobj in &manifest.objects {
        let node = graph
            .nodes
            .iter()
            .find(|n| n.addr == mobj.addr)
            .unwrap_or_else(|| panic!("graph is missing node 0x{:x}", mobj.addr));
        assert_eq!(node.size, mobj.size, "size mismatch at 0x{:x}", mobj.addr);
        assert_eq!(
            node.state,
            manifest_state(mobj.state),
            "state mismatch at 0x{:x}",
            mobj.addr
        );
    }

    // 3. The three-node ring (head/second/tail) clusters into a probable struct.
    let head = manifest_addr(&manifest, "head");
    let second = manifest_addr(&manifest, "second");
    let tail = manifest_addr(&manifest, "tail");
    for addr in [head, second, tail] {
        let node = graph.nodes.iter().find(|n| n.addr == addr).unwrap();
        assert_eq!(
            node.ty.label,
            ObjectLabel::ProbableStruct,
            "ring node 0x{addr:x} label"
        );
        assert!(node.ty.members >= 3, "ring node 0x{addr:x} members");
        // Fix 2: the 0x41 fill bytes must NOT render as fake string fields.
        assert!(
            !node.ty.fields.iter().any(|f| f.kind == FieldKind::String),
            "ring node 0x{addr:x} must not report string fields for fill bytes; fields = {:?}",
            node.ty.fields
        );
    }

    // 4. payload carries a vtable field/evidence pointing at the fake rodata
    // vtable in the read-only file-backed rodata segment.
    let payload = graph
        .nodes
        .iter()
        .find(|n| n.addr == manifest_addr(&manifest, "payload"))
        .unwrap();
    let has_vtable_field = payload.ty.fields.iter().any(|f| f.kind == FieldKind::Vtable);
    let has_vtable_evidence = payload
        .ty
        .evidence
        .iter()
        .any(|e| e.contains("0x7faa00004080") || e.contains("vtable"));
    assert!(
        has_vtable_field || has_vtable_evidence,
        "payload should carry vtable evidence; fields = {:?}, evidence = {:?}",
        payload.ty.fields,
        payload.ty.evidence
    );
    assert!(
        payload.ty.evidence.iter().any(|e| e.contains("0x7faa00004080")),
        "payload vtable evidence must name 0x7faa00004080; evidence = {:?}",
        payload.ty.evidence
    );

    // 5. The freed object is labelled FreedChunk.
    let freed = graph
        .nodes
        .iter()
        .find(|n| n.addr == manifest_addr(&manifest, "freed_slot"))
        .unwrap();
    assert_eq!(freed.ty.label, ObjectLabel::FreedChunk);

    // 6. head is reachable from the stack root.
    let head_node = graph.nodes.iter().find(|n| n.addr == head).unwrap();
    assert!(head_node.reachable_from_root, "head must be root-reachable");
    assert!(head_node.is_root, "head is targeted by a stack/register root");

    // 7. Ring edges are present.
    for (a, b) in [("head", "second"), ("second", "tail"), ("tail", "head")] {
        let from = manifest_addr(&manifest, a);
        let to = manifest_addr(&manifest, b);
        assert!(
            graph.edges.iter().any(|e| e.from == from && e.to == to),
            "missing ring edge {a}->{b}"
        );
    }

    // 8. confirmed_edges semantics: only Object-source redundancy confirms.
    // head has two object sources (payload + tail), so every edge targeting
    // head is confirmed (including the root edges); head->second and
    // second->tail each have a single source and are NOT confirmed.
    let edges_to = |addr: u64| graph.edges.iter().filter(move |e| e.to == addr);
    assert!(
        edges_to(head).all(|e| e.confirmed),
        "all edges targeting head must be confirmed (2 object sources)"
    );
    for (a, b) in [("head", "second"), ("second", "tail")] {
        let from = manifest_addr(&manifest, a);
        let to = manifest_addr(&manifest, b);
        let edge = graph
            .edges
            .iter()
            .find(|e| e.from == from && e.to == to)
            .expect("ring edge");
        assert!(
            !edge.confirmed,
            "single-source edge {a}->{b} must NOT be confirmed"
        );
    }
    assert_eq!(graph.stats.confirmed_edges, 4, "head-confirming edges");

    // Sanity on aggregate statistics.
    assert_eq!(graph.stats.allocated, 4);
    assert_eq!(graph.stats.freed, 1);
    assert_eq!(graph.stats.mmap, 0);
    assert_eq!(graph.stats.clusters, 1, "one probable-struct cluster of 3");
    assert_eq!(graph.stats.root_reachable, 3, "head/second/tail reachable");
    assert_eq!(graph.stats.max_depth, 2, "BFS depth head->second->tail");
}

#[test]
fn json_export_round_trips() {
    let (graph, _manifest) = build_default();

    let v = graph_to_json(&graph);
    let obj = v.as_object().expect("top-level JSON must be an object");
    for key in ["version", "stats", "arenas", "nodes", "edges", "roots"] {
        assert!(obj.contains_key(key), "graph JSON missing key {key}");
    }

    assert_eq!(obj["nodes"].as_array().unwrap().len(), graph.nodes.len());
    assert_eq!(obj["edges"].as_array().unwrap().len(), graph.edges.len());
    assert_eq!(obj["roots"].as_array().unwrap().len(), graph.roots.len());
    assert_eq!(obj["arenas"].as_array().unwrap().len(), graph.arenas.len());

    // Stats are carried through faithfully.
    assert_eq!(obj["stats"]["total_objects"], graph.stats.total_objects);

    // Pretty export parses back to the identical value.
    let pretty = graph_to_json_pretty(&graph);
    let back: serde_json::Value = serde_json::from_str(&pretty).expect("pretty JSON parses");
    assert_eq!(back, v);
}

/// A hand-built anonymous `rw-` heap mapping, mirroring the carve's backing
/// memory without involving the testkit.
fn anon_heap_image(fill: u8) -> (MemoryMap, Vec<u8>) {
    const HEAP: u64 = 0x600000;
    const SIZE: u64 = 0x10000;
    let map = MemoryMap::from_ranges(vec![MemoryRange {
        start: HEAP,
        end: HEAP + SIZE,
        file_offset: 0,
        file_size: SIZE,
        perms: Perms {
            read: true,
            write: true,
            execute: false,
        },
        kind: RangeKind::Anon,
        path: None,
        name: Some("[heap]".into()),
    }]);
    (map, vec![fill; SIZE as usize])
}

fn put_word(bytes: &mut [u8], addr: u64, value: u64) {
    let off = (addr - 0x600000) as usize;
    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn heap_obj(addr: u64, size: u64) -> Object {
    Object {
        addr,
        size,
        state: HeurState::Allocated,
        arena: None,
        chunk_header: addr - 0x10,
        freed_reason: None,
    }
}

#[test]
fn nullable_pointer_column_keeps_struct_cluster() {
    // Fix 3: a column that is a pointer in 2 of 4 members (the other two are
    // NULL) must stay a single probable-struct cluster with a pointer field,
    // not fragment into pointer / non-pointer clusters.
    let (map, mut bytes) = anon_heap_image(0x41);
    let a = heap_obj(0x600020, 0x20);
    let b = heap_obj(0x600050, 0x20);
    let c = heap_obj(0x600080, 0x20);
    let d = heap_obj(0x6000b0, 0x20);
    put_word(&mut bytes, a.addr, 0x601000);
    put_word(&mut bytes, b.addr, 0x601008);
    put_word(&mut bytes, c.addr, 0);
    put_word(&mut bytes, d.addr, 0);
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![a, b, c, d],
    };

    let graph = build_graph(&image, &inventory, &ScanResult::default());
    assert_eq!(graph.stats.clusters, 1, "nullable pointer column must not split");
    for n in &graph.nodes {
        assert_eq!(n.ty.label, ObjectLabel::ProbableStruct);
        assert!(n.ty.members == 4, "all four instances share one cluster");
        assert!(
            n.ty
                .fields
                .iter()
                .any(|f| f.offset == 0 && f.kind == FieldKind::Pointer),
            "nullable pointer field must be kept at offset 0; fields = {:?}",
            n.ty.fields
        );
    }
}

#[test]
fn three_ascending_integers_not_vector() {
    // Fix 4: a 24-byte struct holding three ascending integers must not be
    // labeled a std::vector just because {w0,w1,w2} are sorted with 8-byte
    // strides. The integers are not mapped, so the begin/end/cap gates reject
    // the vector heuristic and the object falls through to struct clustering.
    let (map, mut bytes) = anon_heap_image(0x00);
    let a = heap_obj(0x600020, 0x18);
    let b = heap_obj(0x600050, 0x18);
    let c = heap_obj(0x600080, 0x18);
    for o in [&a, &b, &c] {
        put_word(&mut bytes, o.addr, 0x8000);
        put_word(&mut bytes, o.addr + 8, 0x10000);
        put_word(&mut bytes, o.addr + 16, 0x18000);
    }
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![a, b, c],
    };

    let graph = build_graph(&image, &inventory, &ScanResult::default());
    assert_eq!(graph.stats.clusters, 1, "three identical structs cluster");
    for n in &graph.nodes {
        assert_eq!(
            n.ty.label,
            ObjectLabel::ProbableStruct,
            "ascending-integer struct must stay a probable struct"
        );
        assert!(
            !n.ty.evidence.iter().any(|e| e.contains("std::vector")),
            "no vector evidence expected; evidence = {:?}",
            n.ty.evidence
        );
    }
}

#[test]
fn libstdcxx_sso_string_detected() {
    // Fix 6: a libstdc++-style SSO string has the SSO marker bit (bit 63) set
    // in the capacity word, the length in word1, and inline characters at
    // offset 0. The old libc++-only heuristic missed these.
    let (map, mut bytes) = anon_heap_image(0x00);
    let o = heap_obj(0x600020, 0x20);
    bytes[(0x600020 - 0x600000) as usize..(0x600020 - 0x600000) as usize + 5]
        .copy_from_slice(b"hello");
    put_word(&mut bytes, o.addr + 8, 5); // inline length
    put_word(&mut bytes, o.addr + 16, (1u64 << 63) | 15); // SSO marker + capacity
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![o],
    };

    let graph = build_graph(&image, &inventory, &ScanResult::default());
    assert_eq!(graph.nodes.len(), 1);
    assert_eq!(
        graph.nodes[0].ty.label,
        ObjectLabel::StdString,
        "libstdc++ SSO string must be detected; evidence = {:?}",
        graph.nodes[0].ty.evidence
    );
    assert!(
        graph.nodes[0]
            .ty
            .evidence
            .iter()
            .any(|e| e.contains("SSO")),
        "evidence should describe SSO; evidence = {:?}",
        graph.nodes[0].ty.evidence
    );
}

#[test]
fn freed_node_edges_not_traversed() {
    // Fix 1: BFS must not traverse edges out of a freed chunk (fastbin/fd
    // garbage) nor follow a live pointer INTO a freed chunk. A freed node is
    // reachable only when a root targets it directly (a dangling stack pointer
    // is a UAF hint), and even then its outgoing edges are never expanded.
    let (map, bytes) = anon_heap_image(0x00);
    let a = heap_obj(0x600020, 0x20); // allocated, root-targeted
    let mut f = heap_obj(0x600050, 0x20);
    f.state = HeurState::Freed;
    let g = heap_obj(0x600080, 0x20); // only reachable via f's garbage
    let h = heap_obj(0x6000b0, 0x20); // only reachable via f's garbage
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![a.clone(), f.clone(), g.clone(), h.clone()],
    };

    let scan_result = ScanResult {
        roots: vec![
            Root {
                value: a.addr,
                source: RootSource::Stack,
                addr: 0x7fff_0000_0000,
            },
            // A dangling stack pointer into the freed chunk.
            Root {
                value: f.addr,
                source: RootSource::Stack,
                addr: 0x7fff_0000_0008,
            },
        ],
        edges: vec![
            Edge {
                from: a.addr,
                to: f.addr, // live -> freed: not traversed into
                offset: 0,
                confirmed: false,
                source: EdgeSource::Object,
            },
            Edge {
                from: f.addr,
                to: g.addr, // freed fastbin garbage: not traversed out of
                offset: 0,
                confirmed: false,
                source: EdgeSource::Object,
            },
            Edge {
                from: f.addr,
                to: h.addr, // freed fastbin garbage: not traversed out of
                offset: 8,
                confirmed: false,
                source: EdgeSource::Object,
            },
        ],
        stray_pointers: Vec::new(),
    };

    let graph = build_graph(&image, &inventory, &scan_result);
    let reach = |addr: u64| {
        graph
            .nodes
            .iter()
            .find(|n| n.addr == addr)
            .expect("node")
            .reachable_from_root
    };
    assert!(reach(a.addr), "root-targeted allocated node is reachable");
    assert!(
        reach(f.addr),
        "freed node is reachable when a root points at it directly"
    );
    assert!(
        !reach(g.addr),
        "freed garbage edge must not make its target reachable"
    );
    assert!(
        !reach(h.addr),
        "freed garbage edge must not make its target reachable"
    );
    assert_eq!(graph.stats.root_reachable, 2);
    assert_eq!(graph.stats.max_depth, 0, "no traversal out of freed nodes");
}

#[test]
fn three_pointers_into_distinct_objects_not_vector() {
    // Fix 2: a 24-byte {ptr,ptr,ptr} struct whose three ascending pointers land
    // in three DIFFERENT carved objects must not be labeled a std::vector.
    // 16-byte allocator alignment makes the gaps 8-byte multiples, so the old
    // gate (mapped + %8 + caps) misfired; the new gate requires begin/end/cap
    // to share one allocation.
    let (map, mut bytes) = anon_heap_image(0x00);
    let s1 = heap_obj(0x600020, 0x18);
    let s2 = heap_obj(0x600050, 0x18);
    let s3 = heap_obj(0x600080, 0x18);
    let t1 = heap_obj(0x600100, 0x18);
    let t2 = heap_obj(0x600140, 0x18);
    let t3 = heap_obj(0x600180, 0x18);
    for o in [&s1, &s2, &s3] {
        put_word(&mut bytes, o.addr, t1.addr);
        put_word(&mut bytes, o.addr + 8, t2.addr);
        put_word(&mut bytes, o.addr + 16, t3.addr);
    }
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![s1, s2, s3, t1, t2, t3],
    };

    let graph = build_graph(&image, &inventory, &ScanResult::default());
    for n in &graph.nodes {
        if [0x600020u64, 0x600050, 0x600080].contains(&n.addr) {
            assert_eq!(
                n.ty.label,
                ObjectLabel::ProbableStruct,
                "struct spanning three allocations must not be a vector; node 0x{:x} fields = {:?}",
                n.addr,
                n.ty.fields
            );
            assert!(
                !n.ty.evidence.iter().any(|e| e.contains("std::vector")),
                "no vector evidence expected; evidence = {:?}",
                n.ty.evidence
            );
        }
    }
}

#[test]
fn rodata_string_pointer_is_plain_pointer_not_vtable() {
    // Fix 3: a word pointing into read-only file-backed memory whose first
    // bytes are a printable string (not a code pointer) is a plain pointer,
    // not a vtable field. The word at offset 0 must route through the cluster
    // field classifier (pointer_field): word1/word2 are large integers so the
    // std::string heuristics do not hijack the object first.
    const RODATA: u64 = 0x400000;
    const HEAP: u64 = 0x600000;
    let mut bytes = vec![0u8; 0x1000 + 0x10000];
    bytes[0..11].copy_from_slice(b"hello world");
    let map = MemoryMap::from_ranges(vec![
        MemoryRange {
            start: RODATA,
            end: RODATA + 0x1000,
            file_offset: 0,
            file_size: 0x1000,
            perms: Perms {
                read: true,
                write: false,
                execute: false,
            },
            kind: RangeKind::File,
            path: None,
            name: Some("toy-server.rodata".into()),
        },
        MemoryRange {
            start: HEAP,
            end: HEAP + 0x10000,
            file_offset: 0x1000,
            file_size: 0x10000,
            perms: Perms {
                read: true,
                write: true,
                execute: false,
            },
            kind: RangeKind::Anon,
            path: None,
            name: Some("[heap]".into()),
        },
    ]);
    let a = heap_obj(HEAP + 0x20, 0x20);
    let b = heap_obj(HEAP + 0x50, 0x20);
    let c = heap_obj(HEAP + 0x80, 0x20);
    for o in [&a, &b, &c] {
        let heap_off = |addr: u64| 0x1000 + (addr - HEAP) as usize;
        bytes[heap_off(o.addr)..heap_off(o.addr) + 8].copy_from_slice(&RODATA.to_le_bytes());
        bytes[heap_off(o.addr + 8)..heap_off(o.addr + 8) + 8]
            .copy_from_slice(&0x1000000u64.to_le_bytes());
        bytes[heap_off(o.addr + 16)..heap_off(o.addr + 16) + 8]
            .copy_from_slice(&0x2000000u64.to_le_bytes());
    }
    let image = MappedImage::from_bytes(bytes, map, 8);
    let inventory = HeapInventory {
        arenas: Vec::new(),
        objects: vec![a, b, c],
    };

    let graph = build_graph(&image, &inventory, &ScanResult::default());
    assert!(
        graph.nodes.iter().all(|n| n.ty.label == ObjectLabel::ProbableStruct),
        "rodata-string objects must stay probable structs, not std::string/vector"
    );
    for n in &graph.nodes {
        let f = n
            .ty
            .fields
            .iter()
            .find(|f| f.offset == 0)
            .expect("pointer field at offset 0");
        assert_eq!(
            f.kind,
            FieldKind::Pointer,
            "rodata string pointer must be a plain pointer, not a vtable; fields = {:?}",
            n.ty.fields
        );
        assert!(
            !n.ty.evidence.iter().any(|e| e.contains("vtable")),
            "no vtable evidence expected; evidence = {:?}",
            n.ty.evidence
        );
    }
}
