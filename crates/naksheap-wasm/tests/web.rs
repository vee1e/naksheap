//! Integration tests for the WebAssembly build.
//!
//! These run in a real browser (or Node, under `wasm-bindgen-test`) and assert
//! that the compiled `wasm32` module recovers the same objects from the same
//! fixture as the native build does. The assertions are against
//! `naksheap-testkit`'s ground-truth manifest, not against hand-written
//! expectations, so they check the pipeline rather than restate it.
//!
//!     cargo test -p naksheap-wasm --target wasm32-unknown-unknown
//!     wasm-pack test --headless --chrome crates/naksheap-wasm
//!
//! The reason these exist separately from the library tests is the build
//! itself: the crate must compile with no filesystem, no threads, and no
//! `std::process`, and a linker or `wasm-bindgen` regression would not be
//! caught by testing the libraries natively.

use naksheap_testkit::CoreSpec;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

/// Analyzes a fixture and returns the parsed result JSON, failing the test with
/// the analyzer's own error message if the pipeline rejects it.
fn analyze_fixture(spec: &CoreSpec) -> serde_json::Value {
    let fixture = spec
        .build()
        .expect("fixture spec must be valid: this is a test-authoring bug");
    let json = naksheap_wasm::analyze_js(&fixture.bytes, None)
        .expect("pipeline must accept a well-formed core");
    serde_json::from_str(&json).expect("analyze_js must return valid JSON")
}

/// Every object the manifest knows about must appear in the graph at the same
/// address. This is the property that matters: the native tests already cover
/// the carve logic, and this proves the browser build reaches the same result.
#[wasm_bindgen_test]
fn recovers_every_manifest_object() {
    let spec = CoreSpec::default();
    let fixture = spec.build().expect("fixture");
    let out = analyze_fixture(&spec);

    let nodes = out["graph"]["nodes"].as_array().expect("nodes array");
    let addrs: Vec<u64> = nodes.iter().filter_map(|n| n["addr"].as_u64()).collect();

    let missing: Vec<&str> = fixture
        .manifest
        .objects
        .iter()
        .filter(|o| !addrs.contains(&o.addr))
        .map(|o| o.label.as_str())
        .collect();

    assert!(
        missing.is_empty(),
        "wasm build lost {} of {} manifest objects: {:?}",
        missing.len(),
        fixture.manifest.objects.len(),
        missing
    );
    assert_eq!(
        nodes.len(),
        fixture.manifest.objects.len(),
        "wasm build should carve exactly the manifest objects"
    );
}

/// The state carried in the manifest (allocated vs freed) must survive the
/// round trip. Zombie memory is a documented feature, so silently losing the
/// freed flag would be a real regression.
#[wasm_bindgen_test]
fn preserves_allocated_and_freed_state() {
    let spec = CoreSpec::default();
    let fixture = spec.build().expect("fixture");
    let out = analyze_fixture(&spec);
    let stats = &out["graph"]["stats"];

    let freed_in_manifest = fixture
        .manifest
        .objects
        .iter()
        .filter(|o| o.state == naksheap_testkit::manifest::ObjectState::Freed)
        .count();
    assert!(
        freed_in_manifest > 0,
        "fixture must contain a freed chunk for this test to mean anything"
    );
    assert_eq!(
        stats["freed"].as_u64(),
        Some(freed_in_manifest as u64),
        "freed object count must match the manifest"
    );
    assert!(
        stats["allocated"].as_u64().unwrap_or(0) > 0,
        "fixture must contain allocated chunks"
    );
}

/// The linked-list ring in the default spec must produce a cycle, which is how
/// the graph builder proves it terminates on cyclic heaps.
#[wasm_bindgen_test]
fn resolves_the_pointer_ring() {
    let spec = CoreSpec::default();
    let fixture = spec.build().expect("fixture");
    let out = analyze_fixture(&spec);

    let edges = out["graph"]["edges"].as_array().expect("edges array");
    assert!(
        !edges.is_empty(),
        "the ring fixture must produce reference edges"
    );

    // head -> second -> tail -> head: every one of those edges must exist.
    let by_label: std::collections::HashMap<&str, u64> = fixture
        .manifest
        .objects
        .iter()
        .map(|o| (o.label.as_str(), o.addr))
        .collect();
    for (from, to) in [("head", "second"), ("second", "tail"), ("tail", "head")] {
        let (Some(f), Some(t)) = (by_label.get(from), by_label.get(to)) else {
            continue;
        };
        let found = edges
            .iter()
            .any(|e| e["from"].as_u64() == Some(*f) && e["to"].as_u64() == Some(*t));
        assert!(found, "missing expected edge {from} -> {to}");
    }
}

/// A stack root must be reported, and the object it points at must be marked
/// root-reachable. Reachability is computed from registers and stacks, so a
/// browser build that dropped it would still "work" but lose the key signal.
#[wasm_bindgen_test]
fn reports_stack_roots_and_reachability() {
    let spec = CoreSpec::default();
    let fixture = spec.build().expect("fixture");
    let out = analyze_fixture(&spec);

    let roots = out["graph"]["roots"].as_array().expect("roots array");
    assert!(
        !roots.is_empty(),
        "the default spec plants a stack root; it must be found"
    );

    let head = fixture
        .manifest
        .objects
        .iter()
        .find(|o| o.label == "head")
        .expect("head object");
    let nodes = out["graph"]["nodes"].as_array().expect("nodes");
    let head_node = nodes
        .iter()
        .find(|n| n["addr"].as_u64() == Some(head.addr))
        .expect("head node in graph");
    assert_eq!(
        head_node["is_root"].as_bool(),
        Some(true),
        "the planted stack root must mark its target as a root"
    );
    assert_eq!(
        head_node["reachable_from_root"].as_bool(),
        Some(true),
        "a rooted object must be root-reachable"
    );
}

/// Metadata from the ELF notes must survive, because it is how a reader tells
/// which crashed process they are looking at.
#[wasm_bindgen_test]
fn carries_process_metadata() {
    let spec = CoreSpec::default();
    let out = analyze_fixture(&spec);
    let meta = &out["meta"];

    assert_eq!(meta["format"].as_str(), Some("elf64"));
    assert_eq!(meta["process"].as_str(), Some("toy-server"));
    assert_eq!(meta["exec_path"].as_str(), Some("/opt/app/toy-server"));
    assert_eq!(meta["pointer_width"].as_u64(), Some(8));
    assert!(
        meta["threads"].as_u64().unwrap_or(0) >= 1,
        "the fixture has at least one thread with a register set"
    );
    assert_eq!(
        meta["truncated"].as_bool(),
        Some(false),
        "a whole fixture must not be reported as truncated"
    );
}

/// Inferred types carry a confidence and evidence, which is the project's whole
/// claim: a hypothesis with a score, not a bare guess.
#[wasm_bindgen_test]
fn infers_types_with_confidence_and_evidence() {
    let out = analyze_fixture(&CoreSpec::default());
    let nodes = out["graph"]["nodes"].as_array().expect("nodes");

    for n in nodes {
        let conf = n["ty"]["confidence"].as_f64().expect("confidence");
        assert!(
            (0.0..=1.0).contains(&conf),
            "confidence out of range for {}: {conf}",
            n["addr"]
        );
        assert!(
            n["ty"]["name"].as_str().is_some_and(|s| !s.is_empty()),
            "every node needs a display name"
        );
        assert!(
            n["ty"]["evidence"].is_array(),
            "every node needs an evidence list, even if empty"
        );
    }
}

/// Progress must actually be reported, monotonically covering the pipeline.
/// The whole point of the progress callback is a moving bar in the UI, so a
/// version that never calls it would look like a hang.
#[wasm_bindgen_test]
fn reports_progress_through_all_stages() {
    use std::sync::{Arc, Mutex};

    // The sink must be Sync because the scan stage reports from rayon's worker
    // pool, so tests share a Mutex through an Arc rather than an Rc<RefCell<_>>.
    let seen: Arc<Mutex<Vec<(String, f32)>>> = Arc::new(Mutex::new(Vec::new()));
    let fixture = CoreSpec::default().build().expect("fixture");
    // Collect progress on the Rust side, without crossing into JS.
    struct Collector(Arc<Mutex<Vec<(String, f32)>>>);
    impl naksheap_wasm::ProgressSink for Collector {
        fn report(&self, p: naksheap_wasm::Progress) {
            self.0.lock().expect("collector lock").push((
                serde_json::to_string(&p.stage)
                    .unwrap_or_default()
                    .trim_matches('"')
                    .to_string(),
                p.fraction,
            ));
        }
    }
    let opts = naksheap_pointer_scan::ScanOptions::default();
    naksheap_wasm::analyze_with(&fixture.bytes, &opts, &Collector(Arc::clone(&seen)))
        .expect("analysis should succeed");

    let events = seen.lock().expect("collector lock");
    assert!(!events.is_empty(), "progress callback was never invoked");

    let stages: std::collections::HashSet<&str> =
        events.iter().map(|(s, _)| s.as_str()).collect();
    for want in ["parse", "carve", "scan", "infer", "serialize"] {
        assert!(
            stages.contains(want),
            "stage {want:?} never reported; saw {stages:?}"
        );
    }

    // Fractions must be sane and finish at 1.0.
    for (stage, f) in events.iter() {
        assert!(
            (0.0..=1.0).contains(f),
            "fraction out of range during {stage}: {f}"
        );
    }
    let last = events.last().expect("non-empty").1;
    assert!(
        (last - 1.0).abs() < 1e-6,
        "progress must finish at 1.0, ended at {last}"
    );
}

/// A large scan must be throttled, not one callback per object. A UI that
/// receives 100k callbacks per second is slower than the analysis it is
/// reporting on, and this is a regression that is invisible in small fixtures.
#[wasm_bindgen_test]
fn throttles_progress_on_a_large_dump() {
    use std::sync::{Arc, Mutex, MutexGuard};

    let n = 3000u32;
    let mut spec = CoreSpec::default();
    for i in 0..n {
        let next = (i + 1) % n;
        let o = naksheap_testkit::SpecObject::new(format!("bulk{i}"), 0x40).ptr(
            0,
            format!("bulk{next}"),
        );
        spec.objects.push(o);
    }
    // The spec's default heap segment is sized for five objects; growing the
    // object list without growing the segment fails validation with a
    // HeapLayout error rather than producing a small fixture.
    spec.heap_size = (n as u64 + 8) * 0x1000;

    let fixture = spec.build().expect("fixture for large spec");
    let count: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
    struct Counter(Arc<Mutex<usize>>);
    impl naksheap_wasm::ProgressSink for Counter {
        fn report(&self, _p: naksheap_wasm::Progress) {
            *self.0.lock().expect("counter lock") += 1;
        }
    }

    let opts = naksheap_pointer_scan::ScanOptions::default();
    naksheap_wasm::analyze_with(&fixture.bytes, &opts, &Counter(Arc::clone(&count)))
        .expect("large analysis should succeed");

    let guard: MutexGuard<usize> = count.lock().expect("counter lock");
    let events = *guard;
    // Throttle target is ~200 updates for the scan; allow generous slack for
    // the stage transitions, but it must not scale with object count.
    assert!(
        events < 1000,
        "progress reported {events} times for {n} objects; it must be throttled"
    );
    assert!(
        events > 10,
        "progress reported only {events} times; the bar would never move"
    );
}

/// The in-browser size guard must reject an oversized input with a message
/// that tells the user what to do instead, rather than dying with an opaque
/// allocation failure.
#[wasm_bindgen_test]
fn rejects_input_over_the_browser_limit() {
    let opts = naksheap_pointer_scan::ScanOptions::default();
    // Constructing a real dump this large is wasteful; the check happens
    // before parsing, so an oversized slice of zeros must be rejected on size
    // alone.
    let big = vec![0u8; naksheap_wasm::MAX_INPUT_BYTES + 1];
    let err = naksheap_wasm::analyze_with(&big, &opts, &naksheap_wasm::NoProgress)
        .err()
        .expect("oversized input must be rejected");
    let msg = err.to_string();
    assert!(
        msg.contains("over the") && msg.contains("limit"),
        "error should explain the limit, got: {msg}"
    );
}

/// Garbage input must produce a clean error, never a panic. A panic inside wasm
/// aborts the module and leaves the worker dead with no message.
#[wasm_bindgen_test]
fn rejects_garbage_without_panicking() {
    let opts = naksheap_pointer_scan::ScanOptions::default();
    for junk in [
        vec![],
        vec![0u8; 64],
        b"not a core dump at all, just text".to_vec(),
    ] {
        let r = naksheap_wasm::analyze_with(&junk, &opts, &naksheap_wasm::NoProgress);
        assert!(r.is_err(), "garbage input must be rejected: {junk:?}");
    }
}

/// A truncated core must be flagged rather than silently producing partial
/// results, matching the CLI's `warning: core file appears truncated`.
#[wasm_bindgen_test]
fn flags_a_truncated_core() {
    let spec = CoreSpec::default();
    let mut fixture = spec.build().expect("fixture");
    // Cut the file in half: the PT_LOAD ranges now extend past the end.
    fixture.bytes.truncate(fixture.bytes.len() / 2);
    let opts = naksheap_pointer_scan::ScanOptions::default();
    let out = naksheap_wasm::analyze_with(&fixture.bytes, &opts, &naksheap_wasm::NoProgress);
    if let Ok(analysis) = out {
        assert_eq!(
            analysis.meta["truncated"].as_bool(),
            Some(true),
            "a halved core must be reported as truncated"
        );
    }
}
