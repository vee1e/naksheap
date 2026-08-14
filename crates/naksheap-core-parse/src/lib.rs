//! naksheap-core-parse
//!
//! Parses core dumps / memory images (ELF core, Windows minidump) into a
//! memory map + address space that downstream analysis crates consume.

pub mod elf;
pub mod error;
pub mod image;
pub mod maps;
pub mod minidump;
pub mod notes;

pub use error::{Error, Result};
pub use image::{
    open, AddressSpace, CoreFile, CoreFormat, MappedImage, ThreadContext,
};
pub use maps::{MemoryMap, MemoryRange, Perms, RangeKind};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_at_binary_search() {
        let mut ranges = vec![
            MemoryRange {
                start: 0x400000,
                end: 0x401000,
                file_offset: 0,
                file_size: 0x1000,
                perms: Perms { read: true, write: false, execute: true },
                kind: RangeKind::File,
                path: None,
                name: None,
            },
            MemoryRange {
                start: 0x7fff0000,
                end: 0x80000000,
                file_offset: 0x1000,
                file_size: 0x10000,
                perms: Perms { read: true, write: true, execute: false },
                kind: RangeKind::Anon,
                path: None,
                name: None,
            },
        ];
        let map = MemoryMap::from_ranges(std::mem::take(&mut ranges));
        assert!(map.range_at(0x400500).is_some());
        assert!(map.range_at(0x7fff1234).is_some());
        assert!(map.range_at(0x7fff0000).is_some());
        assert!(map.range_at(0x3fffff).is_none());
        assert!(map.range_at(0x80000000).is_none());
        assert!(map.range_at(0x401000).is_none()); // gap between ranges
        assert!(map.range_at(0x7fff0000).is_some());
    }

    #[test]
    fn reader_words() {
        let bytes: Vec<u8> = 0x1122334455667788u64.to_le_bytes().to_vec();
        let mut r = notes::Reader::new(&bytes, true);
        assert_eq!(r.u64().unwrap(), 0x1122334455667788);
        assert_eq!(r.remaining(), 0);
    }
}
