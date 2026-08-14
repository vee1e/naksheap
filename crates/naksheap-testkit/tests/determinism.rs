//! Determinism: identical specs must produce byte-for-byte identical cores
//! and identical manifests; distinct specs must produce distinct output.

use naksheap_testkit::{CoreSpec, Fixture, SpecObject};

#[test]
fn build_twice_is_identical() {
    let spec = CoreSpec::default();
    let a = Fixture::from_spec(&spec).expect("a");
    let b = Fixture::from_spec(&spec).expect("b");
    assert_eq!(a.bytes, b.bytes);
    assert_eq!(a.manifest, b.manifest);
    assert_eq!(
        a.manifest_json().expect("json"),
        b.manifest_json().expect("json")
    );
}

#[test]
fn spec_round_trip_is_deterministic() {
    // A spec serialized to JSON and back must rebuild the same bytes.
    let spec = CoreSpec::default();
    let json = serde_json::to_string(&spec).expect("to json");
    let back: CoreSpec = serde_json::from_str(&json).expect("from json");
    let a = Fixture::from_spec(&spec).expect("original");
    let b = Fixture::from_spec(&back).expect("round-tripped");
    assert_eq!(a.bytes, b.bytes, "JSON round-trip must not change output");
}

#[test]
fn spec_changes_change_output() {
    let spec = CoreSpec::default();
    let base = Fixture::from_spec(&spec).expect("base");

    let mut pid_spec = spec.clone();
    pid_spec.pid += 1;
    assert_ne!(
        base.bytes,
        Fixture::from_spec(&pid_spec).expect("pid").bytes,
        "pid must be encoded in the bytes"
    );

    let mut fill_spec = spec.clone();
    fill_spec.objects[0].fill = 0x5a;
    assert_ne!(
        base.bytes,
        Fixture::from_spec(&fill_spec).expect("fill").bytes,
        "fill byte must be encoded in the bytes"
    );

    let mut order_spec = spec.clone();
    order_spec.objects.swap(0, 2);
    assert_ne!(
        base.bytes,
        Fixture::from_spec(&order_spec).expect("order").bytes,
        "object order must be encoded in the bytes"
    );
}

#[test]
fn distinct_specs_distinct_manifest_json() {
    let spec = CoreSpec::default();
    let base = Fixture::from_spec(&spec).expect("base");

    let mut extra = spec.clone();
    extra
        .objects
        .push(SpecObject::new("extra", 0x20));
    let other = Fixture::from_spec(&extra).expect("extra");
    assert_ne!(
        base.manifest_json().expect("a"),
        other.manifest_json().expect("b")
    );
}
