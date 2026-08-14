//! Deterministic synthetic ELF64 core builder.
//!
//! Turns a [`CoreSpec`] into byte-for-byte reproducible ELF64 core bytes plus
//! a ground-truth [`Manifest`]. The layout mirrors a real Linux/glibc crash
//! dump closely enough that `naksheap-core-parse` and
//! `naksheap-allocator-heuristics` recover exactly what the spec asked for:
//!
//! * an `ET_CORE` ELF64 header (x86-64, little-endian);
//! * six program headers: `PT_LOAD` x5 (executable text, libc data, rodata,
//!   heap, stack) plus one `PT_NOTE`;
//! * `NT_PRSTATUS` / `NT_PRPSINFO` / `NT_FILE` notes;
//! * a glibc-style heap blob (chunk headers, a `main_arena`-pointed top
//!   chunk) and the `malloc_state` in a fake libc data blob;
//! * a stack blob holding root pointers.
//!
//! No randomness, no hash-iteration order: identical specs produce identical
//! bytes (asserted by the determinism tests).

use std::collections::HashMap;

use crate::error::{BuilderError, Result};
use crate::manifest::{
    EdgeKind, Manifest, ManifestArena, ManifestEdge, ManifestObject, ManifestRoot, ObjectState,
    RootKind,
};
use crate::spec::{CoreSpec, PointerField, SpecState, Target};

/// ELF class byte for 64-bit little-endian.
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;
/// `ET_CORE`.
const ET_CORE: u16 = 4;
/// `EM_X86_64`.
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_NOTE: u32 = 4;

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_FILE: u32 = 0x46494c45; // "FILE"

/// glibc chunk flag: previous chunk is in use.
const PREV_INUSE: u64 = 1;
/// Byte offset of `top` inside `malloc_state` (64-bit glibc).
const ARENA_TOP_OFFSET: u64 = 0x60;
/// Byte offset of `next` inside `malloc_state` (64-bit glibc).
const ARENA_NEXT_OFFSET: u64 = 0x870;
/// `main_arena` is placed at `libc_base + ARENA_OFFSET` inside the libc blob.
const ARENA_OFFSET: u64 = 0x1000;

const PAGE_SIZE: u64 = 0x1000;
const MIN_USER_SIZE: u64 = 0x10;
/// Minimum size the top chunk is given so `walk_heap` and the arena scorer
/// treat it as a real top chunk.
const TOP_MIN_SIZE: u64 = 0x40;

/// x86_64 `user_regs_struct` indices used by the fixture.
const REG_RBP: usize = 4;
const REG_RDI: usize = 14;
const REG_RIP: usize = 16;
const REG_RSP: usize = 19;

const TEXT_SIZE: u64 = 0x1000;
const LIBC_SIZE: u64 = 0x4000;
/// Read-only, file-backed region mimicking program rodata (vtable/string
/// literals). Sits immediately after the libc blob so it does not overlap it.
const RODATA_BASE: u64 = 0x7faa_0000_4000;
const RODATA_SIZE: u64 = 0x1000;
/// Offset inside the rodata region where the fake vtable lives.
const RODATA_VTABLE_OFFSET: u64 = 0x80;
/// Number of u64 slots in the fake vtable.
const RODATA_VTABLE_SLOTS: usize = 4;

/// A resolved, validated view of a spec: addresses assigned, pointers
/// resolved, and regions proven to fit.
struct Layout {
    text_base: u64,
    libc_base: u64,
    heap_base: u64,
    heap_size: u64,
    stack_base: u64,
    stack_size: u64,
    arena_addr: u64,
    arena_top: u64,
    objects: Vec<ObjectLayout>,
    /// (stack slot address, pointer value).
    stack_roots: Vec<(u64, u64)>,
}

struct ObjectLayout {
    label: String,
    header: u64,
    addr: u64,
    mask: u64,
    user_size: u64,
    state: SpecState,
    fill: u8,
    /// Pointer fields lifted from the spec, with target addresses resolved.
    pointers: Vec<(usize, u64)>,
}

fn align16(x: u64) -> u64 {
    (x + 0xf) & !0xf
}

/// Resolves a target to an absolute address once all object addresses are
/// known.
fn resolve(label_addr: &HashMap<String, u64>, target: &Target) -> Result<u64> {
    match target {
        Target::Absolute(a) => Ok(*a),
        Target::Label(l) => label_addr
            .get(l)
            .copied()
            .ok_or_else(|| BuilderError::UnknownTarget(l.clone())),
    }
}

impl Layout {
    fn compute(spec: &CoreSpec) -> Result<Layout> {
        // Alignments: every region base must be page aligned so the fixture
        // looks like a real mapping and the arena candidate stays 16-aligned.
        for (field, value) in [
            ("text_base", spec.text_base),
            ("libc_base", spec.libc_base),
            ("heap_base", spec.heap_base),
            ("stack_base", spec.stack_base),
        ] {
            if value % PAGE_SIZE != 0 {
                return Err(BuilderError::Misaligned {
                    field: field.to_string(),
                    value,
                });
            }
        }

        let heap_end = spec
            .heap_base
            .checked_add(spec.heap_size)
            .ok_or(BuilderError::HeapLayout {
                heap_base: spec.heap_base,
                heap_end: u64::MAX,
            })?;
        let stack_end = spec
            .stack_base
            .checked_add(spec.stack_size)
            .ok_or(BuilderError::StackLayout {
                stack_base: spec.stack_base,
                stack_end: u64::MAX,
            })?;

        for o in &spec.objects {
            if spec
                .objects
                .iter()
                .filter(|x| x.label == o.label)
                .count()
                > 1
            {
                return Err(BuilderError::DuplicateLabel(o.label.clone()));
            }
        }

        // Pass 1: assign chunk addresses in order. The first chunk header
        // (prev_size) sits at the very start of the heap region, matching the
        // real glibc main-arena layout where carving advances from the brk base.
        let mut cursor = spec.heap_base;
        let mut objects: Vec<ObjectLayout> = Vec::with_capacity(spec.objects.len());
        let mut total_mask: u64 = 0;
        for o in &spec.objects {
            if o.size < MIN_USER_SIZE as usize {
                return Err(BuilderError::ObjectTooSmall {
                    label: o.label.clone(),
                    size: o.size,
                });
            }
            let mask = align16(MIN_USER_SIZE + o.size as u64);
            let user_size = mask - MIN_USER_SIZE;
            objects.push(ObjectLayout {
                label: o.label.clone(),
                header: cursor,
                addr: cursor + MIN_USER_SIZE,
                mask,
                user_size,
                state: o.state,
                fill: o.fill,
                pointers: Vec::new(),
            });
            cursor += mask;
            total_mask += mask;
        }
        let top_header = cursor;
        let required = total_mask + TOP_MIN_SIZE;
        if spec.heap_size < required {
            return Err(BuilderError::HeapLayout {
                heap_base: spec.heap_base,
                heap_end,
            });
        }

        // Pass 2: resolve pointer targets now that every address is known.
        let label_addr: HashMap<String, u64> =
            objects.iter().map(|o| (o.label.clone(), o.addr)).collect();
        let mut fields_by_label: HashMap<&str, &[PointerField]> =
            spec.objects.iter().map(|o| (o.label.as_str(), o.pointers.as_slice())).collect();
        for o in objects.iter_mut() {
            let fields = fields_by_label
                .remove(o.label.as_str())
                .unwrap_or_default();
            for pf in fields {
                if pf.offset + 8 > o.user_size as usize {
                    return Err(BuilderError::PointerOutOfBounds {
                        label: o.label.clone(),
                        offset: pf.offset,
                        size: o.user_size as usize,
                    });
                }
                o.pointers
                    .push((pf.offset, resolve(&label_addr, &pf.target)?));
            }
        }

        let mut stack_roots = Vec::with_capacity(spec.roots.len());
        for r in &spec.roots {
            let slot_end = r.address.checked_add(8).ok_or({
                BuilderError::RootOutsideStack {
                    address: r.address,
                    stack_base: spec.stack_base,
                    stack_end,
                }
            })?;
            if r.address < spec.stack_base || slot_end > stack_end {
                return Err(BuilderError::RootOutsideStack {
                    address: r.address,
                    stack_base: spec.stack_base,
                    stack_end,
                });
            }
            stack_roots.push((r.address, resolve(&label_addr, &r.target)?));
        }

        Ok(Layout {
            text_base: spec.text_base,
            libc_base: spec.libc_base,
            heap_base: spec.heap_base,
            heap_size: spec.heap_size,
            stack_base: spec.stack_base,
            stack_size: spec.stack_size,
            arena_addr: spec.libc_base + ARENA_OFFSET,
            // `main_arena.top` is an mchunkptr (the top chunk's header).
            arena_top: top_header,
            objects,
            stack_roots,
        })
    }
}

/// Main entry point: builds core bytes + manifest for `spec`.
pub(crate) fn build_spec(spec: &CoreSpec) -> Result<(Vec<u8>, Manifest)> {
    let layout = Layout::compute(spec)?;
    let manifest = build_manifest(spec, &layout);
    let bytes = assemble(spec, &layout)?;
    Ok((bytes, manifest))
}

fn build_manifest(spec: &CoreSpec, layout: &Layout) -> Manifest {
    let addr_to_label: HashMap<u64, &str> =
        layout.objects.iter().map(|o| (o.addr, o.label.as_str())).collect();

    let objects: Vec<ManifestObject> = layout
        .objects
        .iter()
        .map(|o| ManifestObject {
            addr: o.addr,
            size: o.user_size,
            state: match o.state {
                SpecState::Allocated => ObjectState::Allocated,
                SpecState::Freed => ObjectState::Freed,
            },
            arena: layout.arena_addr,
            chunk_header: o.header,
            label: o.label.clone(),
        })
        .collect();

    let mut edges = Vec::new();
    for o in &layout.objects {
        for (offset, value) in &o.pointers {
            let (to_label, kind) = match addr_to_label.get(value) {
                Some(label) => (Some((*label).to_string()), EdgeKind::Heap),
                None => (None, EdgeKind::Rodata),
            };
            edges.push(ManifestEdge {
                from_addr: o.addr,
                from_label: o.label.clone(),
                offset: *offset,
                to_addr: *value,
                to_label,
                kind,
            });
        }
    }

    let mut roots: Vec<ManifestRoot> = layout
        .stack_roots
        .iter()
        .map(|(slot, value)| ManifestRoot {
            addr: *slot,
            value: *value,
            kind: RootKind::Stack,
            target_label: addr_to_label.get(value).map(|l| l.to_string()),
        })
        .collect();

    // Register root: RDI points at the first heap object.
    if let Some(first) = layout.objects.first() {
        roots.push(ManifestRoot {
            addr: REG_RDI as u64,
            value: first.addr,
            kind: RootKind::Register,
            target_label: Some(first.label.clone()),
        });
    }

    roots.sort_by_key(|r| (matches!(r.kind, RootKind::Register), r.addr));

    Manifest {
        pointer_width: 8,
        pid: spec.pid,
        process_name: spec.process_name.clone(),
        command_line: spec.command_line.clone(),
        exec_path: spec.exec_path.clone(),
        heap_base: layout.heap_base,
        heap_end: layout.heap_base + layout.heap_size,
        arenas: vec![ManifestArena {
            addr: layout.arena_addr,
            size: layout.heap_size,
            top: layout.arena_top,
            is_main: true,
        }],
        objects,
        roots,
        edges,
    }
}

// ---------------------------------------------------------------------------
// ELF assembly
// ---------------------------------------------------------------------------

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const PHDR_COUNT: usize = 6;

struct Segment {
    p_type: u32,
    p_flags: u32,
    vaddr: u64,
    offset: u64,
    size: u64,
    align: u64,
}

/// Lays out the file: header + program-header table + six segment payloads.
fn plan_segments(layout: &Layout, notes_len: u64) -> Vec<Segment> {
    let mut offset = (EHDR_SIZE + PHDR_COUNT * PHDR_SIZE) as u64;
    let mut push = |p_type: u32, p_flags: u32, vaddr: u64, size: u64, align: u64| {
        let s = Segment {
            p_type,
            p_flags,
            vaddr,
            offset,
            size,
            align,
        };
        offset += size;
        s
    };

    vec![
        push(PT_LOAD, 0b101, layout.text_base, TEXT_SIZE, PAGE_SIZE),
        push(PT_LOAD, 0b110, layout.libc_base, LIBC_SIZE, PAGE_SIZE),
        push(PT_LOAD, 0b100, RODATA_BASE, RODATA_SIZE, PAGE_SIZE),
        push(PT_LOAD, 0b110, layout.heap_base, layout.heap_size, PAGE_SIZE),
        push(PT_LOAD, 0b110, layout.stack_base, layout.stack_size, PAGE_SIZE),
        push(PT_NOTE, 0, 0, notes_len, 4),
    ]
}

fn assemble(spec: &CoreSpec, layout: &Layout) -> Result<Vec<u8>> {
    let notes = build_notes(spec, layout);
    let segments = plan_segments(layout, notes.len() as u64);

    let total = (EHDR_SIZE + PHDR_COUNT * PHDR_SIZE) as u64
        + segments.iter().map(|s| s.size).sum::<u64>();
    let mut file = vec![0u8; total as usize];

    write_ehdr(&mut file);
    for (i, seg) in segments.iter().enumerate() {
        write_phdr(&mut file, i, seg);
    }

    // Executable text blob: deterministic padding.
    let text = &segments[0];
    file[text.offset as usize..(text.offset + text.size) as usize].fill(0xcc);

    // Fake libc data blob: zeros plus the main_arena.
    let libc = &segments[1];
    write_u64_at(
        &mut file,
        libc.offset + (layout.arena_addr - layout.libc_base) + ARENA_TOP_OFFSET,
        layout.arena_top,
    );
    write_u64_at(
        &mut file,
        libc.offset + (layout.arena_addr - layout.libc_base) + ARENA_NEXT_OFFSET,
        layout.arena_addr,
    );
    // `system_mem` / `max_system_mem`: total heap region bytes, as real
    // arenas maintain. Mirrors glibc's `malloc_state` offsets used by
    // naksheap-allocator-heuristics' arena scorer.
    write_u64_at(
        &mut file,
        libc.offset + (layout.arena_addr - layout.libc_base) + 0x888,
        layout.heap_size,
    );
    write_u64_at(
        &mut file,
        libc.offset + (layout.arena_addr - layout.libc_base) + 0x890,
        layout.heap_size,
    );

    // Read-only rodata blob: a fake vtable at `rodata_base + 0x80` whose
    // entries point into the executable text segment.
    let rodata = &segments[2];
    for (i, v) in rodata_vtable(layout).iter().enumerate() {
        write_u64_at(
            &mut file,
            rodata.offset + RODATA_VTABLE_OFFSET + (i as u64 * 8),
            *v,
        );
    }

    // Heap blob: chunk chain + top chunk.
    let heap = &segments[3];
    write_heap(&mut file, heap.offset, layout);

    // Stack blob: root slots near the top of the region.
    let stack = &segments[4];
    for (slot, value) in &layout.stack_roots {
        write_u64_at(&mut file, stack.offset + (slot - layout.stack_base), *value);
    }

    // Notes.
    let notes_seg = &segments[5];
    file[notes_seg.offset as usize..(notes_seg.offset + notes_seg.size) as usize]
        .copy_from_slice(&notes);

    Ok(file)
}

/// The fake vtable entries: pointers into the executable text segment.
fn rodata_vtable(layout: &Layout) -> [u64; RODATA_VTABLE_SLOTS] {
    [
        layout.text_base,
        layout.text_base + 0x20,
        layout.text_base + 0x40,
        layout.text_base + 0x60,
    ]
}

fn write_u64_at(file: &mut [u8], off: u64, value: u64) {
    let off = off as usize;
    file[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_ehdr(file: &mut [u8]) {
    file[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    file[4] = ELFCLASS64;
    file[5] = ELFDATA2LSB;
    file[6] = EV_CURRENT;
    file[7] = 0; // ELFOSABI_SYSV
    file[16..18].copy_from_slice(&ET_CORE.to_le_bytes());
    file[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
    file[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    file[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes()); // e_phoff
    file[52] = EHDR_SIZE as u8; // e_ehsize
    file[54] = PHDR_SIZE as u8; // e_phentsize
    file[56..58].copy_from_slice(&(PHDR_COUNT as u16).to_le_bytes()); // e_phnum
}

fn write_phdr(file: &mut [u8], idx: usize, seg: &Segment) {
    let base = EHDR_SIZE + idx * PHDR_SIZE;
    file[base..base + 4].copy_from_slice(&seg.p_type.to_le_bytes());
    file[base + 4..base + 8].copy_from_slice(&seg.p_flags.to_le_bytes());
    file[base + 8..base + 16].copy_from_slice(&seg.offset.to_le_bytes());
    file[base + 16..base + 24].copy_from_slice(&seg.vaddr.to_le_bytes());
    file[base + 24..base + 32].copy_from_slice(&seg.vaddr.to_le_bytes()); // p_paddr
    file[base + 32..base + 40].copy_from_slice(&seg.size.to_le_bytes()); // p_filesz
    file[base + 40..base + 48].copy_from_slice(&seg.size.to_le_bytes()); // p_memsz
    file[base + 48..base + 56].copy_from_slice(&seg.align.to_le_bytes());
}

/// Writes the glibc chunk chain into the heap blob.
fn write_heap(file: &mut [u8], base: u64, layout: &Layout) {
    // Byte offset of the current chunk header within the heap region; the
    // first chunk header (prev_size) sits at the very start of the region.
    let mut cursor = 0u64;
    for (i, o) in layout.objects.iter().enumerate() {
        // The PREV_INUSE bit of chunk i+1 encodes chunk i's state; the first
        // chunk is preceded by nothing, so it is always "in use".
        let prev_live = if i == 0 {
            true
        } else {
            layout.objects[i - 1].state == SpecState::Allocated
        };
        write_u64_at(file, base + cursor, 0); // prev_size
        write_u64_at(
            file,
            base + cursor + 8,
            o.mask | if prev_live { PREV_INUSE } else { 0 },
        );
        let user_off = base + cursor + MIN_USER_SIZE;
        for k in 0..o.user_size {
            file[(user_off + k) as usize] = o.fill;
        }
        for (pf_offset, value) in &o.pointers {
            write_u64_at(file, user_off + *pf_offset as u64, *value);
        }
        cursor += o.mask;
    }
    // Top chunk: fills the rest of the region. Its PREV_INUSE bit encodes the
    // state of the final real chunk.
    let top_size = layout.heap_size - cursor;
    let prev_live = layout
        .objects
        .last()
        .is_none_or(|o| o.state == SpecState::Allocated);
    write_u64_at(file, base + cursor, 0); // prev_size
    write_u64_at(
        file,
        base + cursor + 8,
        top_size | if prev_live { PREV_INUSE } else { 0 },
    );
}

// ---------------------------------------------------------------------------
// Notes
// ---------------------------------------------------------------------------

fn pad4(buf: &mut Vec<u8>) {
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

struct NoteWriter {
    buf: Vec<u8>,
}

impl NoteWriter {
    fn new() -> Self {
        NoteWriter { buf: Vec::new() }
    }

    fn push(&mut self, n_type: u32, desc: &[u8]) {
        const NAME: &[u8] = b"CORE\0";
        self.buf
            .extend_from_slice(&(NAME.len() as u32).to_le_bytes());
        self.buf
            .extend_from_slice(&(desc.len() as u32).to_le_bytes());
        self.buf.extend_from_slice(&n_type.to_le_bytes());
        self.buf.extend_from_slice(NAME);
        pad4(&mut self.buf);
        self.buf.extend_from_slice(desc);
        pad4(&mut self.buf);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

fn build_notes(spec: &CoreSpec, layout: &Layout) -> Vec<u8> {
    let mut w = NoteWriter::new();
    w.push(NT_PRSTATUS, &prstatus_desc(spec, layout));
    w.push(NT_PRPSINFO, &prpsinfo_desc(spec));
    w.push(NT_FILE, &nt_file_desc(spec, layout));
    w.finish()
}

/// 64-bit `struct elf_prstatus`: signal info, pid, four timevals, then the
/// x86_64 `user_regs_struct` (27 words) at offset `0x70`. Total desc size
/// 0x150; `pr_fpvalid` lives at 0x148 with padding out to 0x150.
fn prstatus_desc(spec: &CoreSpec, layout: &Layout) -> Vec<u8> {
    let mut d = vec![0u8; 0x150];
    d[0..4].copy_from_slice(&11u32.to_le_bytes()); // si_signo = SIGSEGV
    d[0x0c..0x0e].copy_from_slice(&11u16.to_le_bytes()); // pr_cursig (short)
    d[0x20..0x24].copy_from_slice(&spec.pid.to_le_bytes());
    // pr_ppid/pr_pgrp/pr_sid remain zero so the u64 at 0x20 decodes to `pid`.

    let mut regs = [0u64; 27];
    regs[REG_RIP] = layout.text_base + 0x5f0;
    regs[REG_RSP] = layout.stack_base + layout.stack_size - 0x30;
    regs[REG_RBP] = layout.stack_base + layout.stack_size - 0x38;
    if let Some(first) = layout.objects.first() {
        regs[REG_RDI] = first.addr;
    }
    for (i, w) in regs.iter().enumerate() {
        let off = 0x70 + i * 8;
        d[off..off + 8].copy_from_slice(&w.to_le_bytes());
    }
    d
}

/// `struct elf_prpsinfo`: `pr_state`@0x00 (numeric), `pr_sname`@0x01,
/// `pr_fname[16]`@0x28 and `pr_psargs[80]`@0x38, so the fixture places the
/// name/command line there.
fn prpsinfo_desc(spec: &CoreSpec) -> Vec<u8> {
    let mut d = vec![0u8; 0x88];
    d[0] = 0; // pr_state = running
    d[1] = b'R'; // pr_sname
    let fname = spec.process_name.as_bytes();
    let n = fname.len().min(16);
    d[0x28..0x28 + n].copy_from_slice(&fname[..n]);
    let args = spec.command_line.as_bytes();
    let n = args.len().min(80);
    d[0x38..0x38 + n].copy_from_slice(&args[..n]);
    d
}

/// `NT_FILE` descriptor: `count, page_size, count x {start, end, file_ofs}`,
/// then NUL-terminated paths. Order matters: the executable must be first so
/// the parser's executable hint picks it.
fn nt_file_desc(spec: &CoreSpec, layout: &Layout) -> Vec<u8> {
    const LIBC_PATH: &str = "/lib/x86_64-linux-gnu/libc.so.6";
    // A distinct name so the executable hint (first non-library entry) keeps
    // picking the text mapping; rodata is file-backed and read-only.
    const RODATA_PATH: &str = "/opt/app/toy-server.rodata";
    let mut d = Vec::new();
    d.extend_from_slice(&3u64.to_le_bytes()); // count
    d.extend_from_slice(&0x1000u64.to_le_bytes()); // page_size
    // Executable.
    d.extend_from_slice(&layout.text_base.to_le_bytes());
    d.extend_from_slice(&(layout.text_base + TEXT_SIZE).to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    // libc data.
    d.extend_from_slice(&layout.libc_base.to_le_bytes());
    d.extend_from_slice(&(layout.libc_base + LIBC_SIZE).to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    // Read-only rodata (fake vtable region).
    d.extend_from_slice(&RODATA_BASE.to_le_bytes());
    d.extend_from_slice(&(RODATA_BASE + RODATA_SIZE).to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    // Paths.
    d.extend_from_slice(spec.exec_path.as_bytes());
    d.push(0);
    d.extend_from_slice(LIBC_PATH.as_bytes());
    d.push(0);
    d.extend_from_slice(RODATA_PATH.as_bytes());
    d.push(0);
    d
}
