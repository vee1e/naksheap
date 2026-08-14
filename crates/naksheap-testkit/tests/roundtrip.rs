//! Round-trip tests: the synthetic cores must parse cleanly through
//! `naksheap-core-parse` and reconstruct exactly what the spec described.

use naksheap_core_parse::elf::{parse_elf_bytes, parse_elf_core};
use naksheap_core_parse::{CoreFormat, RangeKind};
use naksheap_testkit::{CoreSpec, Fixture};

#[test]
fn default_spec_round_trips_through_parser() {
    let spec = CoreSpec::default();
    let fixture = Fixture::from_spec(&spec).expect("default spec builds");
    let parsed = parse_elf_bytes(&fixture.bytes).expect("core parses");

    assert_eq!(parsed.format, CoreFormat::Elf64);
    assert_eq!(parsed.pointer_width, 8);

    // Process metadata round-trips from NT_PRPSINFO / NT_FILE.
    assert_eq!(parsed.process_name.as_deref(), Some(spec.process_name.as_str()));
    assert_eq!(parsed.command_line.as_deref(), Some(spec.command_line.as_str()));
    assert_eq!(parsed.exec_path.as_deref(), Some(spec.exec_path.as_str()));

    // Exactly the five PT_LOAD segments become memory ranges.
    assert_eq!(parsed.map.len(), 5);

    let text = parsed
        .map
        .iter()
        .find(|r| r.start == spec.text_base)
        .expect("text range");
    assert_eq!(text.kind, RangeKind::File);
    assert!(text.perms.execute && !text.perms.write, "text is r-x");

    let libc = parsed
        .map
        .iter()
        .find(|r| r.start == spec.libc_base)
        .expect("libc range");
    assert_eq!(libc.kind, RangeKind::File);
    assert!(libc.perms.read && libc.perms.write, "libc data is rw-");

    let rodata = parsed
        .map
        .iter()
        .find(|r| r.start == 0x7faa_0000_4000)
        .expect("rodata range");
    assert_eq!(rodata.kind, RangeKind::File, "rodata is file-backed");
    assert!(
        rodata.perms.read && !rodata.perms.write && !rodata.perms.execute,
        "rodata is r-- (not writable)"
    );
    assert!(
        rodata.contains(0x7faa_0000_4080),
        "fake vtable address lives in the rodata range"
    );

    let heap = parsed
        .map
        .iter()
        .find(|r| r.start == spec.heap_base)
        .expect("heap range");
    assert_eq!(heap.kind, RangeKind::Anon);
    assert_eq!(heap.len(), spec.heap_size);

    let stack = parsed
        .map
        .iter()
        .find(|r| r.start == spec.stack_base)
        .expect("stack range");
    assert_eq!(stack.kind, RangeKind::Anon);
    assert_eq!(stack.len(), spec.stack_size);

    // NT_PRSTATUS yields one thread whose tid matches the spec pid.
    assert_eq!(parsed.threads.len(), 1);
    let thread = &parsed.threads[0];
    assert_eq!(thread.tid, spec.pid);
    assert!(
        thread.ip >= spec.text_base && thread.ip < spec.text_base + 0x1000,
        "rip points into text: {:#x}",
        thread.ip
    );
    assert!(
        thread.sp >= spec.stack_base && thread.sp < spec.stack_base + spec.stack_size,
        "rsp points into stack: {:#x}",
        thread.sp
    );
}

#[test]
fn empty_heap_fixture_round_trips() {
    let mut spec = CoreSpec::default();
    spec.objects.clear();
    spec.roots.clear();
    let fixture = Fixture::from_spec(&spec).expect("empty-heap spec builds");
    let parsed = parse_elf_bytes(&fixture.bytes).expect("core parses");
    assert_eq!(parsed.map.len(), 5);
    assert_eq!(fixture.manifest.objects.len(), 0);
}

#[test]
fn written_core_reopens_from_disk() {
    let spec = CoreSpec::default();
    let fixture = Fixture::from_spec(&spec).expect("build");
    let dir = tempfile::tempdir().expect("tempdir");
    let core_path = dir.path().join("core.toy-server");

    fixture.write(&core_path).expect("core written");
    fixture
        .write_manifest(&core_path)
        .expect("manifest written");
    assert!(core_path.exists());

    let manifest_path = core_path.with_file_name(format!(
        "{}.manifest.json",
        core_path.file_name().unwrap().to_string_lossy()
    ));
    assert!(manifest_path.exists(), "manifest file written next to core");

    let reopened = parse_elf_core(&core_path).expect("reopened from disk");
    assert_eq!(reopened.process_name.as_deref(), Some("toy-server"));
    assert_eq!(reopened.exec_path.as_deref(), Some("/opt/app/toy-server"));
    assert_eq!(reopened.threads.len(), 1);
    assert_eq!(reopened.threads[0].tid, spec.pid);
    assert_eq!(reopened.map().len(), 5);
}
