use std::path::Path;

use object::elf::{FileHeader32, FileHeader64};
use object::read::elf::{FileHeader, ProgramHeader};
use object::LittleEndian;

use crate::error::{Error, Result};
use crate::image::{CoreFile, CoreFormat, MappedImage, ThreadContext};
use crate::maps::{MemoryMap, MemoryRange, Perms, RangeKind};
use crate::notes::{
    parse_notes, parse_nt_file, parse_prpsinfo, parse_prstatus, NtFileEntry, Reader, NT_AUXV,
    NT_FILE, NT_PRPSINFO, NT_PRSTATUS,
};

pub struct ParsedCore {
    pub map: MemoryMap,
    pub threads: Vec<ThreadContext>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub exec_path: Option<String>,
    pub pointer_width: u8,
    pub format: CoreFormat,
}

/// Parses an ELF core dump file into a `CoreFile`.
pub fn parse_elf_core(path: &Path) -> Result<CoreFile> {
    let file = std::fs::File::open(path)?;
    // SAFETY: read-only mapping of a file we never mutate.
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data: &[u8] = &mmap;
    let parsed = parse_elf_bytes(data)?;
    let image = MappedImage::from_mmap(mmap, parsed.map.clone(), parsed.pointer_width);
    Ok(CoreFile {
        format: parsed.format,
        image,
        threads: parsed.threads,
        process_name: parsed.process_name,
        command_line: parsed.command_line,
        exec_path: parsed.exec_path,
        maps: parsed.map,
    })
}

/// Parses ELF core bytes in memory (also used by the testkit on synthetic cores).
pub fn parse_elf_bytes(data: &[u8]) -> Result<ParsedCore> {
    if data.len() < 16 {
        return Err(Error::BadNote("ELF file too short for header".into()));
    }
    let class = data[4];
    let data_enc = data[5];
    if data_enc == 2 {
        // All memory reads in this crate are little-endian; a big-endian
        // image would be silently mis-decoded. Reject rather than lie.
        return Err(Error::UnsupportedArch(
            "big-endian ELF cores are not supported yet".to_string(),
        ));
    }
    if data_enc != 1 {
        return Err(Error::UnsupportedArch(format!(
            "unsupported ELF data encoding byte {data_enc}"
        )));
    }
    let ptr_width = match class {
        2 => 8u8,
        1 => 4u8,
        _ => return Err(Error::UnsupportedArch(format!("ELF class byte {class}"))),
    };
    let le = true;
    let format = if ptr_width == 8 { CoreFormat::Elf64 } else { CoreFormat::Elf32 };
    match (class, data_enc) {
        (2, 1) => parse_arch::<FileHeader64<LittleEndian>>(data, ptr_width, le, format),
        (1, 1) => parse_arch::<FileHeader32<LittleEndian>>(data, ptr_width, le, format),
        _ => unreachable!("class/data_enc already validated"),
    }
}

fn parse_arch<T: FileHeader>(
    data: &[u8],
    ptr_width: u8,
    le: bool,
    format: CoreFormat,
) -> Result<ParsedCore>
where
    T::Endian: Copy,
{
    let header = T::parse(data)?;
    let endian = header.endian()?;
    if header.e_type(endian) != object::elf::ET_CORE {
        return Err(Error::BadNote(format!(
            "ELF e_type {:?} is not ET_CORE (4); only core dumps are supported",
            header.e_type(endian)
        )));
    }
    let machine = header.e_machine(endian).0;
    let (reg_count, ip_idx, sp_idx) = reg_layout(machine, ptr_width);
    let phs = header.program_headers(endian, data)?;

    // --- PT_LOAD ranges (authoritative for reading memory) ---
    let mut ranges: Vec<MemoryRange> = Vec::new();
    let mut note_segments: Vec<&[u8]> = Vec::new();
    for ph in phs {
        if ph.p_type(endian) == object::elf::PT_LOAD {
            let vaddr: u64 = ph.p_vaddr(endian).into();
            let filesz: u64 = ph.p_filesz(endian).into();
            let memsz: u64 = ph.p_memsz(endian).into();
            if memsz == 0 {
                continue;
            }
            ranges.push(MemoryRange {
                start: vaddr,
                end: vaddr.saturating_add(memsz),
                file_offset: ph.p_offset(endian).into(),
                file_size: filesz.min(memsz),
                perms: Perms::from_elf_flags(ph.p_flags(endian).0),
                kind: RangeKind::Anon,
                path: None,
                name: None,
            });
        } else if ph.p_type(endian) == object::elf::PT_NOTE {
            let off: u64 = ph.p_offset(endian).into();
            let sz: u64 = ph.p_filesz(endian).into();
            // Bounds-check with checked arithmetic: a crafted PT_NOTE with a
            // huge p_offset/p_filesz must not overflow usize or panic on a
            // slice index.
            let (Some(off), Some(sz)) = (usize::try_from(off).ok(), usize::try_from(sz).ok())
            else {
                continue;
            };
            if let Some(end) = off.checked_add(sz) {
                if end <= data.len() {
                    note_segments.push(&data[off..end]);
                }
            }
        }
    }

    let mut threads: Vec<ThreadContext> = Vec::new();
    let mut process_name = None;
    let mut command_line = None;
    let mut file_entries: Vec<NtFileEntry> = Vec::new();
    let mut auxv: Vec<u64> = Vec::new();

    // Bound the number of threads we materialize so a crafted core with tens
    // of thousands of NT_PRSTATUS notes cannot blow up stack scanning later.
    const MAX_THREADS: usize = 4096;

    for seg in note_segments {
        for note in parse_notes(seg, le)? {
            match note.n_type {
                NT_PRSTATUS
                    if reg_count > 0 && threads.len() < MAX_THREADS => {
                        if let Ok(ps) =
                            parse_prstatus(note.desc, le, ptr_width, reg_count, ip_idx, sp_idx)
                        {
                            threads.push(ThreadContext {
                                tid: ps.tid,
                                reg_words: ps.regs,
                                ip: ps.ip,
                                sp: ps.sp,
                            });
                        }
                    }
                NT_PRPSINFO => {
                    let (n, c) = parse_prpsinfo(note.desc, le, ptr_width);
                    process_name = process_name.or(n);
                    command_line = command_line.or(c);
                }
                NT_FILE => {
                    if let Ok(files) = parse_nt_file(note.desc, le, ptr_width) {
                        file_entries = files;
                    }
                }
                NT_AUXV => auxv.extend(decode_auxv(note.desc, le, ptr_width)),
                _ => {}
            }
        }
    }
    // --- Overlay file-backing info from NT_FILE ---
    for r in ranges.iter_mut() {
        if let Some(e) = best_overlap(r, &file_entries) {
            r.kind = RangeKind::File;
            r.path = Some(e.path.clone());
            r.name = e.path.rsplit('/').next().map(|s| s.to_string());
        } else {
            r.name = Some(
                if r.perms.write && !r.perms.execute {
                    "[anon rw-]".to_string()
                } else if r.perms.execute {
                    "[anon r-x]".to_string()
                } else {
                    "[anon --]".to_string()
                },
            );
        }
    }

    let map = MemoryMap::from_ranges(ranges);
    // Best-effort: pick the executable from NT_FILE as the "main executable" hint.
    // (Full AT_EXECFN resolution requires reading the stack image; deferred.)
    let exec_path = guess_executable(&file_entries);
    Ok(ParsedCore {
        map,
        threads,
        process_name,
        command_line,
        exec_path,
        pointer_width: ptr_width,
        format,
    })
}

/// Heuristic executable detection from NT_FILE: the first entry whose path is
/// not a well-known library. Only used as an informational hint.
fn guess_executable(entries: &[NtFileEntry]) -> Option<String> {
    for e in entries {
        let base = e.path.rsplit('/').next().unwrap_or(&e.path);
        let base = base.to_ascii_lowercase();
        let is_lib = base.starts_with("lib") && base.ends_with(".so")
            || base == "ld-linux-x86-64.so.2"
            || base == "linux-vdso.so.1"
            || base.contains(".so.");
        if !is_lib && !base.is_empty() {
            return Some(e.path.clone());
        }
    }
    None
}

fn decode_auxv(desc: &[u8], le: bool, ptr_bytes: u8) -> Vec<u64> {
    let mut r = Reader::new(desc, le);
    let mut out = Vec::new();
    while let (Ok(t), Ok(v)) = (r.word(ptr_bytes), r.word(ptr_bytes)) {
        out.push(t);
        out.push(v);
        if t == 0 {
            break;
        }
    }
    out
}

fn best_overlap<'a>(r: &MemoryRange, entries: &'a [NtFileEntry]) -> Option<&'a NtFileEntry> {
    let mut best: Option<(u64, &NtFileEntry)> = None;
    for e in entries {
        let lo = r.start.max(e.start);
        let hi = r.end.min(e.end);
        if hi > lo {
            let overlap = hi - lo;
            if best.as_ref().is_none_or(|(b, _)| overlap > *b) {
                best = Some((overlap, e));
            }
        }
    }
    best.map(|(_, e)| e)
}

/// Register-array layout per machine for NT_PRSTATUS parsing.
/// x86_64: user_regs_struct (27), rip=16, rsp=19.
/// x86: elf_gregset_t (17), eip=12, esp=15 (UESP; index 16 is SS).
/// aarch64: user_pt_regs (34), pc=32, sp=31.
/// Others: (0,0,0) disables register extraction.
fn reg_layout(machine: u16, ptr_width: u8) -> (usize, usize, usize) {
    match (ptr_width, machine) {
        (8, 62) => (27, 16, 19),   // EM_X86_64
        (8, 183) => (34, 32, 31),  // EM_AARCH64
        (4, 3) => (17, 12, 15),    // EM_386
        _ => (0, 0, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auxv_decode_stops_at_null() {
        let mut v = Vec::new();
        for (t, x) in [(9u64, 0x7fff1234u64), (6, 0x7fff1000), (0, 0)] {
            v.extend_from_slice(&t.to_le_bytes());
            v.extend_from_slice(&x.to_le_bytes());
        }
        let out = decode_auxv(&v, true, 8);
        assert_eq!(out, vec![9, 0x7fff1234, 6, 0x7fff1000, 0, 0]);
    }

    #[test]
    fn executable_hint_skips_libs() {
        let entries = vec![
            NtFileEntry { start: 0x7f, end: 0x8, file_offset: 0, path: "/lib/x86_64-linux-gnu/libc.so.6".into() },
            NtFileEntry { start: 0x40, end: 0x41, file_offset: 0, path: "/opt/app/server".into() },
        ];
        assert_eq!(guess_executable(&entries), Some("/opt/app/server".to_string()));
    }
}
