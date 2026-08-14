use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Perms {
    pub read: bool,
    pub write: bool,
    pub execute: bool,
}

impl Perms {
    pub fn from_elf_flags(flags: u32) -> Self {
        Perms {
            read: flags & 0b100 != 0,
            write: flags & 0b010 != 0,
            execute: flags & 0b001 != 0,
        }
    }

    pub fn readable(self) -> bool {
        self.read
    }

    pub fn writable(self) -> bool {
        self.write
    }

    pub fn executable(self) -> bool {
        self.execute
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RangeKind {
    /// Backed by a file on disk (executable, library, mmap'd file).
    File,
    /// Anonymous private/shared memory (heap, stack, anon mmaps).
    Anon,
    /// Backing unknown (e.g. raw minidump regions).
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRange {
    pub start: u64,
    pub end: u64,
    /// Byte offset into the dump file where this range's contents live.
    pub file_offset: u64,
    /// Number of bytes of this range actually present in the dump file
    /// (may be less than `end - start` for bss / sparse regions).
    pub file_size: u64,
    pub perms: Perms,
    pub kind: RangeKind,
    /// Backing file path when known (from NT_FILE / /proc maps).
    pub path: Option<String>,
    /// Human friendly name (e.g. "[heap]", "[stack]", basename of path).
    pub name: Option<String>,
}

impl MemoryRange {
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub fn is_writable(&self) -> bool {
        self.perms.write
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MemoryMap {
    ranges: Vec<MemoryRange>,
}

impl MemoryMap {
    /// Builds a map from an unsorted range list, sorting by start address.
    pub fn from_ranges(mut ranges: Vec<MemoryRange>) -> Self {
        ranges.sort_by_key(|r| (r.start, r.end));
        MemoryMap { ranges }
    }

    pub fn iter(&self) -> std::slice::Iter<'_, MemoryRange> {
        self.ranges.iter()
    }

    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Returns the range containing `addr`, if any. Binary search over sorted ranges.
    pub fn range_at(&self, addr: u64) -> Option<&MemoryRange> {
        let idx = self.ranges.partition_point(|r| r.start <= addr);
        if idx == 0 {
            return None;
        }
        let r = &self.ranges[idx - 1];
        if r.contains(addr) {
            Some(r)
        } else {
            None
        }
    }

    pub fn anon_ranges(&self) -> impl Iterator<Item = &MemoryRange> {
        self.ranges.iter().filter(|r| r.kind == RangeKind::Anon)
    }

    pub fn writable_ranges(&self) -> impl Iterator<Item = &MemoryRange> {
        self.ranges.iter().filter(|r| r.perms.write)
    }

    /// Sum of bytes physically present in the dump.
    pub fn total_bytes(&self) -> u64 {
        self.ranges.iter().map(|r| r.file_size).sum()
    }
}
