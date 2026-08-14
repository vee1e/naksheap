#![allow(clippy::field_reassign_with_default)]
//! Invalid specs must be rejected with a precise `BuilderError` before any
//! bytes are produced.

use naksheap_testkit::{BuilderError, CoreSpec, Fixture, SpecObject, SpecRoot, Target};

fn expect_err(spec: CoreSpec, variant: fn(&BuilderError) -> bool, name: &str) {
    match Fixture::from_spec(&spec) {
        Err(err) => {
            assert!(variant(&err), "expected {name}, got: {err}");
        }
        Ok(_) => panic!("spec should have failed with {name}"),
    }
}

#[test]
fn object_too_small_is_rejected() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("tiny", 0x8)];
    expect_err(
        spec,
        |e| matches!(e, BuilderError::ObjectTooSmall { .. }),
        "ObjectTooSmall",
    );
}

#[test]
fn duplicate_labels_are_rejected() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![
        SpecObject::new("dup", 0x20),
        SpecObject::new("dup", 0x30),
    ];
    expect_err(
        spec,
        |e| matches!(e, BuilderError::DuplicateLabel(l) if l == "dup"),
        "DuplicateLabel",
    );
}

#[test]
fn pointer_out_of_bounds_is_rejected() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("small", 0x20).ptr(0x20, "other")];
    expect_err(
        spec,
        |e| matches!(e, BuilderError::PointerOutOfBounds { .. }),
        "PointerOutOfBounds",
    );
}

#[test]
fn unknown_target_label_is_rejected() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("a", 0x20).ptr(0, "ghost")];
    spec.roots.clear();
    expect_err(
        spec,
        |e| matches!(e, BuilderError::UnknownTarget(l) if l == "ghost"),
        "UnknownTarget",
    );
}

#[test]
fn root_outside_stack_is_rejected() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("a", 0x20)];
    spec.roots = vec![SpecRoot {
        address: spec.stack_base - 8,
        target: Target::Label("a".to_string()),
    }];
    expect_err(
        spec,
        |e| matches!(e, BuilderError::RootOutsideStack { .. }),
        "RootOutsideStack",
    );

    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("a", 0x20)];
    spec.roots = vec![SpecRoot {
        address: spec.stack_base + spec.stack_size - 4,
        target: Target::Label("a".to_string()),
    }];
    expect_err(
        spec,
        |e| matches!(e, BuilderError::RootOutsideStack { .. }),
        "RootOutsideStack (slot crosses stack end)",
    );
}

#[test]
fn heap_too_small_is_rejected() {
    let mut spec = CoreSpec::default();
    // Default five objects need 0x150 bytes of heap; give it less.
    spec.heap_size = 0x100;
    expect_err(
        spec,
        |e| matches!(e, BuilderError::HeapLayout { .. }),
        "HeapLayout",
    );
}

#[test]
fn misaligned_bases_are_rejected() {
    let mut spec = CoreSpec::default();
    spec.heap_base = 0x7f00_0000_0001;
    expect_err(
        spec,
        |e| matches!(e, BuilderError::Misaligned { .. }),
        "Misaligned heap_base",
    );

    let mut spec = CoreSpec::default();
    spec.stack_base = 0x7fff_0000_0ff0;
    expect_err(
        spec,
        |e| matches!(e, BuilderError::Misaligned { .. }),
        "Misaligned stack_base",
    );
}

#[test]
fn error_messages_are_actionable() {
    let mut spec = CoreSpec::default();
    spec.objects = vec![SpecObject::new("tiny", 0x8)];
    let err = Fixture::from_spec(&spec).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("tiny"), "message mentions the label: {msg}");
    assert!(msg.contains("0x10"), "message mentions the minimum: {msg}");
}
