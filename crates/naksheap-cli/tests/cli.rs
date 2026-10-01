//! Integration tests for the `naksheap` CLI binary.

use std::path::Path;
use std::process::{Command, Output};

use naksheap_testkit::CoreSpec;

/// Runs the `naksheap` binary with `args`, returning the captured output.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_naksheap"))
        .args(args)
        .output()
        .expect("failed to spawn naksheap binary")
}

fn run_ok(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "`naksheap {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Builds the default fixture and writes the core dump into `dir`.
fn write_fixture(dir: &Path) -> (std::path::PathBuf, naksheap_testkit::Fixture) {
    let fixture = CoreSpec::default().build().expect("build fixture");
    let core = dir.join("core.elf");
    fixture.write(&core).expect("write fixture core");
    (core, fixture)
}

#[test]
fn info_lists_process_and_heap_range() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, fixture) = write_fixture(dir.path());
    let stdout = run_ok(&["info", core.to_str().unwrap()]);

    assert!(stdout.contains("format: elf64"), "stdout: {stdout}");
    assert!(stdout.contains(&fixture.manifest.process_name), "stdout: {stdout}");
    assert!(stdout.contains(&fixture.manifest.command_line), "stdout: {stdout}");
    assert!(stdout.contains(&fixture.manifest.exec_path), "stdout: {stdout}");
    assert!(stdout.contains("[heap]"), "heap range should be marked: {stdout}");
    assert!(stdout.contains("threads: 1"), "stdout: {stdout}");
}

#[test]
fn heap_prints_expected_objects() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, fixture) = write_fixture(dir.path());
    let stdout = run_ok(&["heap", core.to_str().unwrap()]);

    assert!(stdout.contains("arenas (1):"), "stdout: {stdout}");
    assert!(stdout.contains("counts:"), "stdout: {stdout}");
    for obj in &fixture.manifest.objects {
        assert!(
            stdout.contains(&format!("0x{:x}", obj.addr)),
            "expected object 0x{:x} ({}) in stdout:\n{stdout}",
            obj.addr,
            obj.label
        );
    }
}

#[test]
fn maps_lists_ranges_with_heap_marker() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, _fixture) = write_fixture(dir.path());
    let stdout = run_ok(&["maps", core.to_str().unwrap()]);

    assert!(stdout.contains("memory map"), "stdout: {stdout}");
    assert!(stdout.contains(" r-x "), "stdout: {stdout}");
    assert!(stdout.contains(" rw- "), "stdout: {stdout}");
    assert!(stdout.contains("[heap]"), "heap range should be marked: {stdout}");
}

#[test]
fn graph_json_is_valid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, _fixture) = write_fixture(dir.path());
    let stdout = run_ok(&["graph", core.to_str().unwrap(), "--json"]);

    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("graph --json must print valid JSON");
    assert!(value.get("stats").is_some(), "missing stats: {value}");
    assert!(value.get("nodes").is_some(), "missing nodes: {value}");
    assert!(value.get("edges").is_some(), "missing edges: {value}");
    assert!(value["stats"]["total_objects"].as_u64().unwrap() >= 5, "stdout: {value}");
}

#[test]
fn graph_ascii_tree_default() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, _fixture) = write_fixture(dir.path());
    let stdout = run_ok(&["graph", core.to_str().unwrap()]);

    assert!(stdout.contains("naksheap object graph"), "stdout: {stdout}");
    assert!(stdout.contains("probable struct"), "stdout: {stdout}");
    assert!(stdout.contains("+0x00 pointer"), "stdout: {stdout}");
}

#[test]
fn graph_dot_and_html_write_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (core, _fixture) = write_fixture(dir.path());
    let out_dir = dir.path().join("out");
    let stdout = run_ok(&[
        "graph",
        core.to_str().unwrap(),
        "--dot",
        "--html",
        "--json",
        "--out",
        out_dir.to_str().unwrap(),
    ]);

    assert!(stdout.contains("graph.dot"), "stdout: {stdout}");
    assert!(stdout.contains("report.html"), "stdout: {stdout}");
    assert!(stdout.contains("graph.json"), "stdout: {stdout}");
    assert!(out_dir.join("graph.dot").is_file());
    assert!(out_dir.join("report.html").is_file());
    assert!(out_dir.join("graph.json").is_file());

    let dot = std::fs::read_to_string(out_dir.join("graph.dot")).expect("read graph.dot");
    assert!(dot.starts_with("digraph"), "dot: {dot}");
    let html = std::fs::read_to_string(out_dir.join("report.html")).expect("read report.html");
    // The report must be self-contained: no CDN fetch, no placeholders left
    // unsubstituted, and the renderer actually present.
    assert!(
        !html.contains("https://") && !html.contains("http://"),
        "report references an external resource: {html}"
    );
    assert!(!html.contains("__DATA__"), "unsubstituted data blob");
    assert!(html.contains("requestAnimationFrame"), "renderer missing");
}

#[test]
fn self_test_passes() {
    let stdout = run_ok(&["self-test"]);
    assert!(stdout.contains("self-test OK"), "stdout: {stdout}");
}
