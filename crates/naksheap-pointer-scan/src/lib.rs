//! naksheap-pointer-scan
//!
//! Given a parsed core dump image plus the heap objects carved by
//! `naksheap-allocator-heuristics`, this crate discovers reference edges
//! between objects (which carved object points to which) by scanning object
//! user data and thread roots (registers + stacks). The resulting edge set is
//! what an object-graph builder consumes.
//!
//! # Design
//!
//! * [`index_objects`] builds an [`ObjectIndex`]: a start-sorted table of
//!   carved objects with binary-search stabbing queries
//!   ([`ObjectIndex::target_at`]).
//! * Object user areas are scanned in parallel (via `rayon`) at
//!   [`ScanOptions::alignment`] word strides; every pointer that resolves into
//!   a carved object becomes an [`Edge`].
//! * Thread registers and stacks are scanned for root pointers; stack words
//!   that resolve to objects become both [`Root`]s and stack [`Edge`]s.
//! * A cheap second pass computes the [`Edge::confirmed`] flag: a target
//!   referenced by >= 2 distinct *object* sources, or an object target that
//!   holds a back-pointer into its referrer, marks its edges confirmed.
//!   Stack/register (root) edges never confirm a target, so a stale stack or
//!   register word cannot elevate an edge; freed objects' stale free-list
//!   (fd/bk) words are likewise excluded, so they cannot confirm an edge
//!   either.
//!
//! The scanner never panics on garbage input; unresolved non-zero pointers are
//! reported as [`ScanResult::stray_pointers`] (capped at
//! [`ScanOptions::max_strays`]).

mod index;
mod roots;
mod scan;

pub use index::{index_objects, ObjectIndex};
pub use roots::collect_roots;
pub use scan::scan;

/// Where a root pointer candidate came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RootSource {
    /// A general-purpose register holding the pointer.
    Register,
    /// A word read from the thread's stack.
    Stack,
}

/// A root pointer candidate: a value that points into a carved object.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Root {
    /// The pointer value.
    pub value: u64,
    /// Where this root came from.
    pub source: RootSource,
    /// For [`RootSource::Stack`] roots, the stack address the word was read
    /// from; `0` for register roots.
    pub addr: u64,
}

/// Provenance of a reference edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeSource {
    /// The edge was found in another object's user area.
    Object,
    /// The edge is a stack word pointing into an object.
    Stack,
    /// The edge is a register word pointing into an object.
    Register,
}

/// A reference edge from a source object (or a root) to a target object.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Edge {
    /// Source object address for [`EdgeSource::Object`] edges, or `0` for
    /// stack/register (root) edges.
    pub from: u64,
    /// Target object address.
    pub to: u64,
    /// Offset of the pointer word inside the source object's user area
    /// (object edges), or the stack address the word was read from
    /// (stack edges). `0` for register edges.
    pub offset: u64,
    /// `true` when the target is back-referenced or referenced by >= 2
    /// distinct *object* sources. Stack and register (root) edges never count
    /// as confirming sources, so a single stale stack word or register value
    /// cannot confirm an edge. Edges originating in freed objects are stale
    /// free-list (fd/bk) words and do not confirm a target either.
    pub confirmed: bool,
    /// Where this edge was found.
    pub source: EdgeSource,
}

/// Result of a full pointer scan.
#[derive(Debug, Clone, serde::Serialize, Default)]
pub struct ScanResult {
    /// All discovered reference edges (object, stack, register).
    pub edges: Vec<Edge>,
    /// Root pointer candidates found in thread registers and stacks.
    pub roots: Vec<Root>,
    /// Non-zero words that pointed outside every carved object. Collected
    /// deterministically: per-object lists are merged, then
    /// sorted/deduplicated and capped at [`ScanOptions::max_strays`], so the
    /// surviving strays never depend on parallel scheduling order.
    pub stray_pointers: Vec<u64>,
}

/// Controls which parts of the address space the scanner visits.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Word alignment required (default 8 for 64-bit targets).
    pub alignment: u64,
    /// Whether to scan object user areas for intra-heap pointers.
    pub scan_objects: bool,
    /// Whether to scan each thread's stack for pointers into objects.
    pub scan_stacks: bool,
    /// Whether to treat each thread's register words as roots.
    pub scan_registers: bool,
    /// Treat freed objects as valid edge targets (default true; callers may
    /// filter).
    pub include_freed_targets: bool,
    /// Cap on stray pointers collected to bound memory (default 100_000).
    pub max_strays: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            alignment: 8,
            scan_objects: true,
            scan_stacks: true,
            scan_registers: true,
            include_freed_targets: true,
            max_strays: 100_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use naksheap_allocator_heuristics::{HeapInventory, Object, ObjectState};
    use naksheap_core_parse::{
        MappedImage, MemoryMap, MemoryRange, Perms, RangeKind, ThreadContext,
    };

    const HEAP_START: u64 = 0x600000;
    const STACK_START: u64 = 0x7fff0000;
    const HEAP_SIZE: u64 = 0x10000;
    const STACK_SIZE: u64 = 0x10000;

    fn obj(addr: u64, size: u64, state: ObjectState) -> Object {
        Object {
            addr,
            size,
            state,
            arena: None,
            chunk_header: addr - 0x10,
            freed_reason: None,
        }
    }

    fn write_word(bytes: &mut [u8], map: &MemoryMap, addr: u64, val: u64) {
        let r = map.range_at(addr).expect("addr must be mapped");
        let delta = addr - r.start;
        let off = (r.file_offset + delta) as usize;
        bytes[off..off + 8].copy_from_slice(&val.to_le_bytes());
    }

    struct Ctx {
        map: MemoryMap,
        bytes: Vec<u8>,
    }

    impl Ctx {
        fn put(&mut self, addr: u64, val: u64) {
            write_word(&mut self.bytes, &self.map, addr, val);
        }

        fn image(self) -> MappedImage {
            MappedImage::from_bytes(self.bytes, self.map, 8)
        }
    }

    fn ctx() -> Ctx {
        let ranges = vec![
            MemoryRange {
                start: 0x400000,
                end: 0x401000,
                file_offset: 0x0,
                file_size: 0x1000,
                perms: Perms {
                    read: true,
                    write: false,
                    execute: true,
                },
                kind: RangeKind::File,
                path: None,
                name: Some("lib".into()),
            },
            MemoryRange {
                start: HEAP_START,
                end: HEAP_START + HEAP_SIZE,
                file_offset: 0x1000,
                file_size: HEAP_SIZE,
                perms: Perms {
                    read: true,
                    write: true,
                    execute: false,
                },
                kind: RangeKind::Anon,
                path: None,
                name: Some("[heap]".into()),
            },
            MemoryRange {
                start: STACK_START,
                end: STACK_START + STACK_SIZE,
                file_offset: 0x1000 + HEAP_SIZE,
                file_size: STACK_SIZE,
                perms: Perms {
                    read: true,
                    write: true,
                    execute: false,
                },
                kind: RangeKind::Anon,
                path: None,
                name: Some("[stack]".into()),
            },
        ];
        let map = MemoryMap::from_ranges(ranges);
        Ctx {
            map,
            bytes: vec![0u8; 0x21000],
        }
    }

    fn thread(sp: u64, reg_words: Vec<u64>) -> ThreadContext {
        ThreadContext {
            tid: 1,
            reg_words,
            ip: 0x400500,
            sp,
        }
    }

    #[test]
    fn target_at_empty_index() {
        let index = index_objects(&[]);
        assert!(index.target_at(0x610000).is_none());
    }

    #[test]
    fn target_at_overlap_picks_smallest() {
        let objects = vec![
            obj(0x610000, 0x40, ObjectState::Allocated),
            obj(0x610010, 0x20, ObjectState::Allocated),
        ];
        let index = index_objects(&objects);
        assert_eq!(index.target_at(0x610018).unwrap().addr, 0x610010);
        assert_eq!(index.target_at(0x610008).unwrap().addr, 0x610000);
        assert_eq!(index.target_at(0x610000).unwrap().addr, 0x610000);
        assert!(index.target_at(0x610040).is_none());
        assert!(index.target_at(0x0).is_none());
    }

    #[test]
    fn basic_object_edge() {
        let mut c = ctx();
        c.put(0x600110, 0x600200);
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600200, 0x40, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert_eq!(res.edges.len(), 1);
        let e = &res.edges[0];
        assert_eq!(e.from, 0x600100);
        assert_eq!(e.to, 0x600200);
        assert_eq!(e.offset, 0x10);
        assert_eq!(e.source, EdgeSource::Object);
        assert!(res.roots.is_empty());
        assert!(res.stray_pointers.is_empty());
    }

    #[test]
    fn self_pointer_skipped() {
        let mut c = ctx();
        c.put(0x600120, 0x600100); // degenerate self-loop at exactly obj.addr
        c.put(0x600128, 0x600110); // pointer into own interior -> valid self edge
        let image = c.image();
        let objects = vec![obj(0x600100, 0x40, ObjectState::Allocated)];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert!(
            !res
                .edges
                .iter()
                .any(|e| e.from == 0x600100 && e.to == 0x600100 && e.offset == 0x20),
            "pointer equal to obj.addr must be skipped"
        );
        assert!(
            res.edges
                .iter()
                .any(|e| e.from == 0x600100 && e.to == 0x600100 && e.offset == 0x28),
            "pointer into own interior is a valid self edge"
        );
    }

    #[test]
    fn stray_pointer_not_edge() {
        let mut c = ctx();
        c.put(0x600210, 0x600500); // B's user area points into empty heap space
        let image = c.image();
        let objects = vec![obj(0x600200, 0x40, ObjectState::Allocated)];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert!(res.edges.is_empty());
        assert!(res.stray_pointers.contains(&0x600500));
    }

    #[test]
    fn stack_and_register_roots() {
        let mut c = ctx();
        c.put(0x7fff1000, 0x600200);
        c.put(0x7fff1008, 0x600300);
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600200, 0x40, ObjectState::Allocated),
            obj(0x600300, 0x40, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let index = index_objects(&inventory.objects);
        let threads = vec![thread(0x7fff1000, vec![0x600300, 0, 0xdeadbeef])];

        let roots = collect_roots(&image, &threads, &index);
        assert!(
            roots
                .iter()
                .any(|r| r.value == 0x600200 && r.source == RootSource::Stack && r.addr == 0x7fff1000)
        );
        assert!(
            roots
                .iter()
                .any(|r| r.value == 0x600300 && r.source == RootSource::Register && r.addr == 0)
        );
        assert!(!roots.iter().any(|r| r.value == 0xdeadbeef));

        let res = scan(&image, &inventory, &threads, &ScanOptions::default());
        assert!(
            res.edges.iter().any(|e| e.from == 0
                && e.to == 0x600200
                && e.offset == 0x7fff1000
                && e.source == EdgeSource::Stack)
        );
        assert!(
            res.edges.iter().any(|e| e.from == 0
                && e.to == 0x600300
                && e.offset == 0
                && e.source == EdgeSource::Register)
        );
    }

    #[test]
    fn freed_target_filtering() {
        let mut c = ctx();
        c.put(0x600110, 0x600400);
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600400, 0x40, ObjectState::Freed),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };

        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert!(
            res.edges
                .iter()
                .any(|e| e.from == 0x600100 && e.to == 0x600400 && e.offset == 0x10)
        );

        let opts = ScanOptions {
            include_freed_targets: false,
            ..ScanOptions::default()
        };
        let res = scan(&image, &inventory, &[], &opts);
        assert!(!res.edges.iter().any(|e| e.to == 0x600400));
    }

    #[test]
    fn confirmed_two_sources() {
        let mut c = ctx();
        c.put(0x600110, 0x600200); // A -> B
        c.put(0x600118, 0x600300); // A -> C
        c.put(0x600210, 0x600300); // B -> C  (second object source for C)
        c.put(0x600138, 0x600180); // A -> E  (E's only source)
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated), // A
            obj(0x600180, 0x40, ObjectState::Allocated), // E
            obj(0x600200, 0x40, ObjectState::Allocated), // B
            obj(0x600300, 0x40, ObjectState::Allocated), // C
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let threads = vec![thread(0x7fff1000, vec![0x600300])];
        let res = scan(&image, &inventory, &threads, &ScanOptions::default());

        let e_ab = res
            .edges
            .iter()
            .find(|e| e.from == 0x600100 && e.to == 0x600200)
            .expect("A->B edge");
        assert!(!e_ab.confirmed, "B referenced by a single source only");

        for e in res.edges.iter().filter(|e| e.to == 0x600300) {
            assert!(e.confirmed, "C referenced by >= 2 sources");
        }

        let e_ae = res
            .edges
            .iter()
            .find(|e| e.from == 0x600100 && e.to == 0x600180)
            .expect("A->E edge");
        assert!(!e_ae.confirmed, "E referenced by a single source only");
    }

    #[test]
    fn stack_word_does_not_confirm_object_edge() {
        let mut c = ctx();
        c.put(0x600110, 0x600200); // A -> B  (B's only object source)
        c.put(0x7fff1000, 0x600200); // stale stack word also points at B
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated), // A
            obj(0x600200, 0x40, ObjectState::Allocated), // B
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let threads = vec![thread(0x7fff1000, vec![])];
        let res = scan(&image, &inventory, &threads, &ScanOptions::default());

        let e_ab = res
            .edges
            .iter()
            .find(|e| e.from == 0x600100 && e.to == 0x600200)
            .expect("A->B object edge");
        assert!(
            !e_ab.confirmed,
            "a stack word must not confirm an object edge (single object source)"
        );

        let e_stack = res
            .edges
            .iter()
            .find(|e| e.source == EdgeSource::Stack && e.to == 0x600200)
            .expect("stack edge");
        assert!(
            !e_stack.confirmed,
            "a stack edge is never confirmed by the >= 2 rule"
        );
    }

    #[test]
    fn back_pointer_confirms_edge() {
        let mut c = ctx();
        c.put(0x600110, 0x600200); // A -> B
        c.put(0x600210, 0x600100); // B -> A (back-pointer)
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600200, 0x40, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        let e_ab = res
            .edges
            .iter()
            .find(|e| e.from == 0x600100 && e.to == 0x600200)
            .expect("A->B edge");
        assert!(e_ab.confirmed, "A->B confirmed by B's back-pointer");
    }

    #[test]
    fn dedup_collapses_duplicate_edges() {
        let mut c = ctx();
        c.put(0x600110, 0x600200); // A -> B (offset 0x10)
        c.put(0x600120, 0x600200); // A -> B again (offset 0x20, distinct)
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600200, 0x40, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert_eq!(res.edges.len(), 2);
        assert!(
            res.edges
                .iter()
                .filter(|e| e.from == 0x600100 && e.to == 0x600200)
                .count()
                == 2
        );
    }

    #[test]
    fn in_use_chunk_spill_area_scanned() {
        // A 0x20 glibc chunk reports usable size 0x10, but an in-use chunk's
        // data may extend 8 bytes into the next chunk's prev_size (e.g. a
        // 24-byte std::vector stores its 3rd word at offset 0x10). The scan
        // must cover that spill area for Allocated chunks.
        let mut c = ctx();
        c.put(0x600110, 0x600200); // word at offset 0x10 (spill area) -> B
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x10, ObjectState::Allocated), // chunk 0x20
            obj(0x600200, 0x20, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert!(
            res.edges.iter().any(|e| e.from == 0x600100
                && e.to == 0x600200
                && e.offset == 0x10),
            "pointer in the +8 spill area must be an edge for in-use chunks"
        );
    }

    #[test]
    fn freed_chunk_spill_area_not_scanned() {
        // Freed chunks carry free-list data in their user area, so no +8 spill.
        let mut c = ctx();
        c.put(0x600110, 0x600200); // would be the spill word if scanned
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x10, ObjectState::Freed),
            obj(0x600200, 0x20, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let res = scan(&image, &inventory, &[], &ScanOptions::default());
        assert!(
            !res.edges.iter().any(|e| e.from == 0x600100 && e.offset == 0x10),
            "freed chunks must not get spill-area scanning"
        );
    }

    #[test]
    fn options_turn_off_scans() {
        let mut c = ctx();
        c.put(0x600110, 0x600200);
        c.put(0x7fff1000, 0x600200);
        let image = c.image();
        let objects = vec![
            obj(0x600100, 0x40, ObjectState::Allocated),
            obj(0x600200, 0x40, ObjectState::Allocated),
        ];
        let inventory = HeapInventory {
            arenas: Vec::new(),
            objects,
        };
        let threads = vec![thread(0x7fff1000, vec![0x600200])];
        let opts = ScanOptions {
            scan_objects: false,
            scan_stacks: false,
            scan_registers: true,
            ..ScanOptions::default()
        };
        let res = scan(&image, &inventory, &threads, &opts);
        assert!(res.edges.iter().all(|e| e.source == EdgeSource::Register));
        assert!(res.roots.iter().all(|r| r.source == RootSource::Register));
    }
}
