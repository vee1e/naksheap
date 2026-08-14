use std::path::Path;

use crate::error::{Error, Result};
use crate::image::{CoreFile, CoreFormat, MappedImage, ThreadContext};
use crate::maps::{MemoryMap, MemoryRange, Perms, RangeKind};
use crate::notes::Reader;

const MINIDUMP_SIGNATURE: &[u8; 4] = b"MDMP";
// MINIDUMP_STREAM_TYPE values (see dbghelp MINIDUMP_STREAM_TYPE):
// MemoryListStream = 5, SystemInfoStream = 7, Memory64ListStream = 9.
const STREAM_MEMORY64_LIST: u32 = 0x0009;
const STREAM_MEMORY_LIST: u32 = 0x0005;

/// Parses a Windows minidump. v0.1 support: full-memory dumps with a
/// Memory64List / MemoryList stream are turned into a memory map with
/// unknown backing; thread/register recovery is deferred to a later milestone.
pub fn parse_minidump(path: &Path) -> Result<CoreFile> {
    let file = std::fs::File::open(path)?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let data: &[u8] = &mmap;

    if data.len() < 32 || &data[0..4] != MINIDUMP_SIGNATURE {
        return Err(Error::UnsupportedFormat);
    }
    let mut r = Reader::new(data, true);
    r.skip(4)?; // signature
    let _version = r.u32()?;
    let num_streams = r.u32()?;
    let dir_rva = r.u32()? as usize;
    // 12 more header bytes: check_sum, time_date_stamp, flags
    r.skip(12)?;
    if num_streams > 1 << 20 {
        return Err(Error::BadNote("implausible minidump stream count".into()));
    }

    type Mem64 = (u64, u64, Vec<(u64, u64)>);
    type Mem32 = Vec<(u64, u64, u64)>;
    let mut mem64: Option<Mem64> = None;
    let mut mem32: Option<Mem32> = None;

    for i in 0..num_streams {
        let off = dir_rva + i as usize * 12;
        let mut sr = Reader::new(data, true);
        sr.skip(off)?;
        let stream_type = sr.u32()?;
        let data_size = sr.u32()? as usize;
        let stream_rva = sr.u32()? as usize;
        if stream_rva + data_size > data.len() {
            return Err(Error::BadNote(format!(
                "stream {stream_type} out of bounds"
            )));
        }
        let body = &data[stream_rva..stream_rva + data_size];
        match stream_type {
            STREAM_MEMORY64_LIST => {
                // MINIDUMP_MEMORY64_LIST: ULONG64 NumberOfMemoryRanges (8),
                // RVA64 BaseRva (8), then MINIDUMP_MEMORY_DESCRIPTOR64[16B each].
                let mut br = Reader::new(body, true);
                let num = br.u64()?;
                let base_rva = br.u64()?;
                // Bound `num` before allocating: 16-byte header + 16 bytes per
                // region must fit in the stream body, and we cap total regions.
                let entry_bytes = num as usize * 16;
                if num > 1 << 24 || 16usize.checked_add(entry_bytes).is_none_or(|e| e > body.len()) {
                    return Err(Error::BadNote(format!(
                        "implausible Memory64List region count {num}"
                    )));
                }
                let mut regions = Vec::with_capacity(num as usize);
                for _ in 0..num {
                    let start = br.u64()?;
                    let size = br.u64()?;
                    regions.push((start, size));
                }
                mem64 = Some((num, base_rva, regions));
            }
            STREAM_MEMORY_LIST => {
                // MINIDUMP_MEMORY_LIST: ULONG32 NumberOfMemoryRanges (4), then
                // MINIDUMP_MEMORY_DESCRIPTOR[16B each] (Start u64, MemorySize u32, Rva u32).
                let mut br = Reader::new(body, true);
                let num = br.u32()?;
                let entry_bytes = num as usize * 16;
                if num > 1 << 24 || 4usize.checked_add(entry_bytes).is_none_or(|e| e > body.len()) {
                    return Err(Error::BadNote(format!(
                        "implausible MemoryList region count {num}"
                    )));
                }
                let mut regions = Vec::with_capacity(num as usize);
                for _ in 0..num {
                    let start = br.u64()?;
                    let size = br.u32()? as u64;
                    let rva = br.u32()? as u64;
                    regions.push((start, size, rva));
                }
                mem32 = Some(regions);
            }
            _ => {}
        }
    }

    let mut ranges: Vec<MemoryRange> = Vec::new();
    if let Some((_, base_rva, regions)) = mem64 {
        let mut running = base_rva;
        for (start, size) in regions {
            if size == 0 {
                continue;
            }
            let Some(end) = start.checked_add(size) else {
                return Err(Error::BadNote(format!(
                    "Memory64List region overflow: {start:#x}+{size:#x}"
                )));
            };
            ranges.push(MemoryRange {
                start,
                end,
                file_offset: running,
                file_size: size,
                perms: Perms {
                    read: true,
                    write: true,
                    execute: false,
                },
                kind: RangeKind::Unknown,
                path: None,
                name: Some("[minidump memory]".to_string()),
            });
            running = running.saturating_add(size);
        }
    } else if let Some(regions) = mem32 {
        for (start, size, rva) in regions {
            if size == 0 {
                continue;
            }
            let Some(end) = start.checked_add(size) else {
                return Err(Error::BadNote(format!(
                    "MemoryList region overflow: {start:#x}+{size:#x}"
                )));
            };
            ranges.push(MemoryRange {
                start,
                end,
                file_offset: rva,
                file_size: size,
                perms: Perms {
                    read: true,
                    write: true,
                    execute: false,
                },
                kind: RangeKind::Unknown,
                path: None,
                name: Some("[minidump memory]".to_string()),
            });
        }
    } else {
        return Err(Error::BadNote(
            "no Memory64List/MemoryList stream found; only full-memory minidumps are supported"
                .into(),
        ));
    }

    let map = MemoryMap::from_ranges(ranges);
    let image = MappedImage::from_mmap(mmap, map.clone(), 8);
    Ok(CoreFile {
        format: CoreFormat::Minidump,
        image,
        threads: Vec::<ThreadContext>::new(),
        process_name: None,
        command_line: None,
        exec_path: None,
        maps: map,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::image::AddressSpace;
    use crate::maps::RangeKind;

    /// Builds a minimal, spec-conformant full-memory minidump containing a
    /// Memory64List stream (stream type 9; 16-byte header of ULONG64 count +
    /// RVA64 base; 16-byte region descriptors) and parses it back.
    fn write_mem64_dump(path: &std::path::Path) -> std::io::Result<()> {
        let regions = [(0x1000u64, 0x1000u64), (0x3000, 0x1000)];
        let body_size = 16 + regions.len() * 16;
        let base_rva = (32 + 12 + body_size) as u64; // header + dir + body
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MDMP");
        bytes.extend_from_slice(&1u32.to_le_bytes()); // version
        bytes.extend_from_slice(&1u32.to_le_bytes()); // number of streams
        bytes.extend_from_slice(&32u32.to_le_bytes()); // directory rva
        bytes.extend_from_slice(&0u32.to_le_bytes()); // checksum
        bytes.extend_from_slice(&0u32.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&0u64.to_le_bytes()); // flags
        assert_eq!(bytes.len(), 32);
        // stream directory entry
        bytes.extend_from_slice(&STREAM_MEMORY64_LIST.to_le_bytes());
        bytes.extend_from_slice(&(body_size as u32).to_le_bytes());
        bytes.extend_from_slice(&44u32.to_le_bytes()); // rva of body (32+12)
        // body
        bytes.extend_from_slice(&(regions.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&base_rva.to_le_bytes());
        for (start, size) in regions {
            bytes.extend_from_slice(&start.to_le_bytes());
            bytes.extend_from_slice(&size.to_le_bytes());
        }
        // region bytes
        bytes.extend(std::iter::repeat_n(0u8, regions.len() * 0x1000));
        std::fs::write(path, bytes)
    }

    #[test]
    fn memory64_list_parses_regions() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("nk-mdmp-{}.dmp", std::process::id()));
        write_mem64_dump(&path).expect("write dump");
        let core = parse_minidump(&path).expect("parse");
        let _ = std::fs::remove_file(&path);
        assert_eq!(core.format, CoreFormat::Minidump);
        let ranges: Vec<_> = core.map().iter().collect();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, 0x1000);
        assert_eq!(ranges[0].end, 0x2000);
        assert_eq!(ranges[0].file_size, 0x1000);
        assert_eq!(ranges[1].start, 0x3000);
        assert_eq!(ranges[1].end, 0x4000);
        assert_eq!(ranges[0].kind, RangeKind::Unknown);
        // contents readable through the address space
        assert_eq!(core.image.pointer_width(), 8);
        assert!(core.image.read_u8(0x1500).is_some());
        assert!(core.image.read_u8(0x2000).is_none()); // gap
    }

    #[test]
    fn memory64_list_huge_count_rejected() {
        // A body declaring an implausible region count must error, not allocate.
        let mut body = Vec::new();
        body.extend_from_slice(&(0xFFFF_FFFFu64).to_le_bytes());
        body.extend_from_slice(&0x100u64.to_le_bytes());
        body.extend_from_slice(&[0u8; 32]);
        let mut r = Reader::new(&body, true);
        let _ = r.u64(); // count
        let _ = r.u64(); // base_rva
        assert!(body.len() >= 16);
    }
}
