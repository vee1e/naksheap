use std::path::Path;

use crate::error::{Error, Result};
use crate::maps::{MemoryMap, MemoryRange};

/// A thread snapshot extracted from a core dump: registers + identifiers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThreadContext {
    pub tid: i32,
    /// All general-purpose registers as native-width words (architecture
    /// register order). Consumed by pointer-scan as candidate root pointers.
    pub reg_words: Vec<u64>,
    pub ip: u64,
    pub sp: u64,
}

/// Read access over a virtual address space backed by a dump image.
pub trait AddressSpace {
    /// Returns the bytes at `addr..addr+len` if present in the dump.
    fn read_bytes(&self, addr: u64, len: u64) -> Option<&[u8]>;

    fn read_u8(&self, addr: u64) -> Option<u8> {
        self.read_bytes(addr, 1).map(|b| b[0])
    }

    fn read_u16(&self, addr: u64) -> Option<u16> {
        let b = self.read_bytes(addr, 2)?;
        Some(u16::from_le_bytes([b[0], b[1]]))
    }

    fn read_u32(&self, addr: u64) -> Option<u32> {
        let b = self.read_bytes(addr, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let b = self.read_bytes(addr, 8)?;
        Some(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// Reads a native-width pointer-sized word.
    fn read_word(&self, addr: u64) -> Option<u64> {
        if self.pointer_width() == 8 {
            self.read_u64(addr)
        } else {
            self.read_u32(addr).map(u64::from)
        }
    }

    /// Writes are not supported; always `None`.
    fn write_bytes(&self, _addr: u64, _bytes: &[u8]) -> Option<()> {
        None
    }

    fn pointer_width(&self) -> u8;

    fn map(&self) -> &MemoryMap;

    fn range_at(&self, addr: u64) -> Option<&MemoryRange> {
        self.map().range_at(addr)
    }

    fn is_mapped(&self, addr: u64) -> bool {
        self.range_at(addr).is_some()
    }

    /// True if `addr` points into a file-backed (executable/library) mapping.
    fn is_file_backed(&self, addr: u64) -> bool {
        self.range_at(addr)
            .map(|r| r.kind == crate::maps::RangeKind::File)
            .unwrap_or(false)
    }
}

/// Backing store for a parsed dump image: either a memmapped file or an
/// owned byte buffer (for synthetic/in-memory cores in tests).
enum Backing {
    Mapped(memmap2::Mmap),
    Owned(std::sync::Arc<[u8]>),
}

impl Backing {
    fn slice(&self, offset: u64, len: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let end = usize::try_from(offset.checked_add(len)?).ok()?;
        match self {
            Backing::Mapped(m) => m.get(start..end),
            Backing::Owned(b) => b.get(start..end),
        }
    }

    fn len(&self) -> u64 {
        match self {
            Backing::Mapped(m) => m.len() as u64,
            Backing::Owned(b) => b.len() as u64,
        }
    }
}

/// The parsed dump image: byte store + memory map + pointer width.
pub struct MappedImage {
    backing: Backing,
    map: MemoryMap,
    pointer_width: u8,
}

impl MappedImage {
    /// Length of the backing byte store (the dump file or synthetic buffer).
    pub fn file_len(&self) -> u64 {
        self.backing.len()
    }

    /// True when at least one mapped range extends past the end of the backing
    /// file — i.e. the dump was truncated or the file is a partial snapshot.
    /// Reads into the missing area return `None`, so results are silently
    /// partial; callers should warn.
    pub fn is_truncated(&self) -> bool {
        self.map.iter().any(|r| {
            r.file_offset.saturating_add(r.file_size) > self.file_len()
        })
    }

    /// Builds an image from an owned byte buffer (used by the testkit for
    /// synthetic cores and by unit tests).
    pub fn from_bytes(bytes: Vec<u8>, map: MemoryMap, pointer_width: u8) -> Self {
        MappedImage {
            backing: Backing::Owned(std::sync::Arc::from(bytes)),
            map,
            pointer_width,
        }
    }

    /// Wraps an existing read-only mmap (used by the ELF core parser so the
    /// file is only mapped once).
    pub(crate) fn from_mmap(mmap: memmap2::Mmap, map: MemoryMap, pointer_width: u8) -> Self {
        MappedImage {
            backing: Backing::Mapped(mmap),
            map,
            pointer_width,
        }
    }
}

impl AddressSpace for MappedImage {
    fn read_bytes(&self, addr: u64, len: u64) -> Option<&[u8]> {
        if len == 0 {
            return Some(&[]);
        }
        let r = self.map.range_at(addr)?;
        let delta = addr - r.start;
        if delta >= r.file_size || len > r.file_size - delta {
            return None;
        }
        let file_off = r.file_offset.checked_add(delta)?;
        self.backing.slice(file_off, len)
    }

    fn pointer_width(&self) -> u8 {
        self.pointer_width
    }

    fn map(&self) -> &MemoryMap {
        &self.map
    }
}

/// Parse result for any supported dump format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum CoreFormat {
    Elf64,
    Elf32,
    Minidump,
}

/// A fully parsed core dump / memory image.
pub struct CoreFile {
    pub format: CoreFormat,
    pub image: MappedImage,
    pub threads: Vec<ThreadContext>,
    pub process_name: Option<String>,
    pub command_line: Option<String>,
    pub exec_path: Option<String>,
    /// Reconstructed /proc maps-equivalent (informational).
    pub maps: MemoryMap,
}

impl CoreFile {
    pub fn map(&self) -> &MemoryMap {
        &self.maps
    }
}

/// Opens and parses `path`, sniffing the format from the magic bytes.
pub fn open(path: &Path) -> Result<CoreFile> {
    let mut magic = [0u8; 4];
    {
        use std::io::Read;
        let mut f = std::fs::File::open(path)?;
        f.read_exact(&mut magic)?;
    }
    if magic.starts_with(b"MDMP") {
        crate::minidump::parse_minidump(path)
    } else if magic[0] == 0x7f && magic[1] == b'E' && magic[2] == b'L' && magic[3] == b'F' {
        crate::elf::parse_elf_core(path)
    } else {
        Err(Error::UnsupportedFormat)
    }
}
