#![allow(clippy::field_reassign_with_default)]
//! Ground-truth manifest consistency: the manifest must be exactly what the
//! spec requested (sizes aligned to glibc chunk rules, states, arena, the
//! pointer ring, roots), and must serialize as valid JSON.

use naksheap_testkit::{
    CoreSpec, EdgeKind, Fixture, ObjectState, RootKind, SpecObject, SpecState,
};

fn align16(x: u64) -> u64 {
    (x + 0xf) & !0xf
}

#[test]
fn default_manifest_matches_spec() {
    let spec = CoreSpec::default();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let m = &fixture.manifest;

    assert_eq!(m.pointer_width, 8);
    assert_eq!(m.pid, spec.pid);
    assert_eq!(m.process_name, spec.process_name);
    assert_eq!(m.command_line, spec.command_line);
    assert_eq!(m.exec_path, spec.exec_path);
    assert_eq!(m.heap_base, spec.heap_base);
    assert_eq!(m.heap_end, spec.heap_base + spec.heap_size);

    // Arena: main_arena at libc_base + 0x1000, self-looped, top in the heap.
    assert_eq!(m.arenas.len(), 1);
    let arena = &m.arenas[0];
    assert_eq!(arena.addr, spec.libc_base + 0x1000);
    assert_eq!(arena.size, spec.heap_size);
    assert!(arena.is_main);
    assert!(arena.top >= spec.heap_base && arena.top < m.heap_end);

    // Objects: one per spec, in address order, chunk header immediately below
    // the user pointer, sizes rounded up to glibc's 16-byte rule.
    assert_eq!(m.objects.len(), spec.objects.len());
    let mut prev_end = m.heap_base;
    for (idx, obj) in m.objects.iter().enumerate() {
        let s = &spec.objects[idx];
        assert_eq!(obj.label, s.label);
        assert_eq!(obj.size, align16(0x10 + s.size as u64) - 0x10);
        assert_eq!(obj.arena, arena.addr);
        assert_eq!(obj.chunk_header, obj.addr - 0x10);
        assert!(obj.addr >= prev_end, "objects laid out in address order");
        prev_end = obj.addr + obj.size;
        let expected_state = match s.state {
            SpecState::Allocated => ObjectState::Allocated,
            SpecState::Freed => ObjectState::Freed,
        };
        assert_eq!(obj.state, expected_state, "state for {}", s.label);
    }
    // Default fixture: four allocated objects and one freed slot.
    assert_eq!(
        m.objects
            .iter()
            .filter(|o| o.state == ObjectState::Freed)
            .count(),
        1
    );

    // Edges: the linked-list ring plus payload->head and a rodata edge.
    let ring: Vec<(String, Option<String>, EdgeKind)> = m
        .edges
        .iter()
        .map(|e| (e.from_label.clone(), e.to_label.clone(), e.kind))
        .collect();
    assert!(ring.contains(&("head".into(), Some("second".into()), EdgeKind::Heap)));
    assert!(ring.contains(&("second".into(), Some("tail".into()), EdgeKind::Heap)));
    assert!(ring.contains(&("tail".into(), Some("head".into()), EdgeKind::Heap)));
    assert!(ring.contains(&("payload".into(), Some("head".into()), EdgeKind::Heap)));
    assert!(ring
        .iter()
        .any(|(from, to, kind)| from == "payload" && *kind == EdgeKind::Rodata && to.is_none()));

    // Roots: the stack root plus the RDI register root, both into `head`.
    assert_eq!(m.roots.len(), 2);
    let stack_root = m
        .roots
        .iter()
        .find(|r| r.kind == RootKind::Stack)
        .expect("stack root");
    assert_eq!(stack_root.addr, 0x7fff_0000_3fd0);
    assert_eq!(stack_root.target_label.as_deref(), Some("head"));
    let reg_root = m
        .roots
        .iter()
        .find(|r| r.kind == RootKind::Register)
        .expect("register root");
    assert_eq!(reg_root.target_label.as_deref(), Some("head"));

    // Every manifest edge offset must point at the spec's own pointer fields.
    for edge in &m.edges {
        let spec_obj = spec
            .objects
            .iter()
            .find(|o| o.label == edge.from_label)
            .unwrap_or_else(|| panic!("edge from unknown object {}", edge.from_label));
        assert!(
            spec_obj.pointers.iter().any(|p| p.offset == edge.offset),
            "edge offset {:#x} not declared by {}",
            edge.offset,
            edge.from_label
        );
    }
}

#[test]
fn manifest_serializes_to_json() {
    let fixture = Fixture::from_spec(&CoreSpec::default()).expect("build");
    let json = fixture.manifest_json().expect("json");
    let value: serde_json::Value = serde_json::from_str(&json).expect("parses as json");

    assert_eq!(value["pointer_width"], 8);
    assert_eq!(value["pid"], 4242);
    assert_eq!(value["process_name"], "toy-server");
    assert_eq!(value["arenas"].as_array().map(Vec::len), Some(1));
    assert_eq!(value["objects"].as_array().map(Vec::len), Some(5));
    assert_eq!(value["edges"].as_array().map(Vec::len), Some(5));
    assert_eq!(value["roots"].as_array().map(Vec::len), Some(2));
}

#[test]
fn custom_spec_manifest_is_consistent() {
    // A freed chunk followed by a live one: states must follow the glibc
    // PREV_INUSE rule, not the spec order blindly.
    let mut spec = CoreSpec::default();
    spec.objects = vec![
        SpecObject::new("a", 0x20).freed(),
        SpecObject::new("b", 0x20),
        SpecObject::new("c", 0x40).ptr(0, "a"),
    ];
    spec.roots.clear();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let m = fixture.manifest;

    let a = m.objects.iter().find(|o| o.label == "a").unwrap();
    let b = m.objects.iter().find(|o| o.label == "b").unwrap();
    let c = m.objects.iter().find(|o| o.label == "c").unwrap();
    assert_eq!(a.state, ObjectState::Freed);
    assert_eq!(b.state, ObjectState::Allocated);
    assert_eq!(c.state, ObjectState::Allocated);

    // c -> a is a heap edge at offset 0.
    let edge = m
        .edges
        .iter()
        .find(|e| e.from_label == "c")
        .expect("c has an edge");
    assert_eq!(edge.offset, 0);
    assert_eq!(edge.to_addr, a.addr);
    assert_eq!(edge.to_label.as_deref(), Some("a"));
    assert_eq!(edge.kind, EdgeKind::Heap);
}

#[test]
fn absolute_target_edges_are_rodata() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("buf", 0x40).ptr_abs(0, 0x7faa_0000_4080)];
    spec.roots.clear();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let m = fixture.manifest;
    assert_eq!(m.edges.len(), 1);
    assert_eq!(m.edges[0].kind, EdgeKind::Rodata);
    assert_eq!(m.edges[0].to_addr, 0x7faa_0000_4080);
    assert!(m.edges[0].to_label.is_none());
}

#[test]
fn target_round_trips_through_json() {
    let spec = CoreSpec::default();
    let json = serde_json::to_string(&spec).expect("spec to json");
    let back: CoreSpec = serde_json::from_str(&json).expect("spec from json");
    assert_eq!(spec, back);
    // And both must build byte-identical fixtures (defaults survive JSON).
    let a = Fixture::from_spec(&spec).expect("a");
    let b = Fixture::from_spec(&back).expect("b");
    assert_eq!(a.bytes, b.bytes);
}
