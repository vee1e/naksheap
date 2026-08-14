#![allow(clippy::field_reassign_with_default)]
//! Reconstruction-fidelity test: running the real glibc carving heuristics
//! over the synthetic core must recover exactly the ground-truth manifest.

use naksheap_allocator_heuristics::{carve, ObjectState as HeuristicState};
use naksheap_core_parse::elf::parse_elf_bytes;
use naksheap_core_parse::MappedImage;
use naksheap_testkit::{CoreSpec, Fixture, ObjectState};

fn carve_fixture(fixture: &Fixture) -> naksheap_allocator_heuristics::HeapInventory {
    let parsed = parse_elf_bytes(&fixture.bytes).expect("core parses");
    let image = MappedImage::from_bytes(
        fixture.bytes.clone(),
        parsed.map.clone(),
        parsed.pointer_width,
    );
    carve(&image)
}

fn map_state(s: HeuristicState) -> ObjectState {
    match s {
        HeuristicState::Allocated => ObjectState::Allocated,
        HeuristicState::Freed => ObjectState::Freed,
        HeuristicState::Mmap => ObjectState::Mmap,
        HeuristicState::Unknown => ObjectState::Unknown,
    }
}

#[test]
fn carve_recovers_default_manifest_exactly() {
    let spec = CoreSpec::default();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let inv = carve_fixture(&fixture);

    // The single main_arena is found at its exact address, with the exact
    // top pointer and heap-region size.
    assert_eq!(inv.arenas.len(), fixture.manifest.arenas.len());
    let arena = &inv.arenas[0];
    let expected = &fixture.manifest.arenas[0];
    assert_eq!(arena.addr, expected.addr, "arena address");
    assert_eq!(arena.top, expected.top, "arena top");
    assert_eq!(arena.size, expected.size, "arena region size");
    assert_eq!(arena.is_main, expected.is_main);

    // Every manifest object is recovered with identical address, size,
    // state, arena and chunk header.
    assert_eq!(inv.objects.len(), fixture.manifest.objects.len());
    for (obj, expected) in inv.objects.iter().zip(&fixture.manifest.objects) {
        assert_eq!(obj.addr, expected.addr, "object address");
        assert_eq!(obj.size, expected.size, "object size");
        assert_eq!(map_state(obj.state), expected.state, "object state");
        assert_eq!(obj.arena, Some(expected.arena), "object arena");
        assert_eq!(obj.chunk_header, expected.chunk_header, "chunk header");
    }

    // Spot check the linked-list ring survived carving.
    let labels: Vec<&str> = fixture.manifest.objects.iter().map(|o| o.label.as_str()).collect();
    assert_eq!(labels, vec!["head", "second", "tail", "payload", "freed_slot"]);
}

#[test]
fn carve_recovers_freed_state_from_flags() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![
        naksheap_testkit::SpecObject::new("live", 0x30),
        naksheap_testkit::SpecObject::new("gone", 0x20).freed(),
        naksheap_testkit::SpecObject::new("alive_again", 0x20),
    ];
    spec.roots.clear();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let inv = carve_fixture(&fixture);

    let states: Vec<ObjectState> = inv.objects.iter().map(|o| map_state(o.state)).collect();
    assert_eq!(
        states,
        vec![ObjectState::Allocated, ObjectState::Freed, ObjectState::Allocated],
        "states follow the PREV_INUSE chain"
    );
    assert_eq!(inv.objects[1].addr, fixture.manifest.objects[1].addr);
}
