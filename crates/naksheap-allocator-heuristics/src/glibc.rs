//! glibc ptmalloc carving.
//!
//! Implements the glibc (64-bit) allocator metadata parser: chunk-header
//! walking, `main_arena` discovery, and arena-to-object carving.
//!
//! # Chunk layout (64-bit glibc)
//!
//! A chunk's header sits `0x10` bytes before its user pointer:
//!
//! ```text
//!   header+0x0 : prev_size (8 bytes)
//!   header+0x8 : size (8 bytes), low 3 bits carry flags
//!   header+0x10: user data
//! ```
//!
//! `PREV_INUSE` (bit 0) is stored in the *next* chunk's size field; a cleared
//! bit means the current chunk was freed. `IS_MMAPPED` (bit 1) marks chunks
//! served by `mmap`. The usable size is `(size & !0xF) - 0x10` and the next
//! chunk's header is at `header + (size & !0xF)`.

use std::collections::{HashMap, HashSet};

use naksheap_core_parse::{AddressSpace, MemoryRange, RangeKind};

use crate::{ArenaInfo, HeapInventory, Object, ObjectState};

/// ptmalloc alignment for 64-bit glibc.
pub const MALLOC_ALIGNMENT: u64 = 16;
/// Size of a machine word on 64-bit glibc.
pub const SIZE_SZ: u64 = 8;
/// Size-field flag: previous chunk is in use.
pub const PREV_INUSE: u64 = 1;
/// Size-field flag: chunk was served by `mmap`.
pub const IS_MMAPPED: u64 = 2;
/// Size-field flag: chunk belongs to a non-main arena.
pub const NON_MAIN_ARENA: u64 = 4;
/// Byte offset of `top` inside `malloc_state` (64-bit glibc).
pub const ARENA_TOP_OFFSET: u64 = 0x60;
/// Byte offset of `next` inside `malloc_state` (64-bit glibc).
pub const ARENA_NEXT_OFFSET: u64 = 0x870;
/// Byte offset of `system_mem` inside `malloc_state` (64-bit glibc); on a
/// real arena this is the total system memory of the heap it manages.
pub const ARENA_SYSTEM_MEM_OFFSET: u64 = 0x888;

const PAGE_SIZE: u64 = 0x1000;
/// Minimum accepted chunk size (`size & !0xF`); smaller values are garbage.
const MIN_CHUNK_SIZE: u64 = 0x20;
/// Upper bound on carved objects (amplification guard).
pub const MAX_OBJECTS: usize = 5_000_000;
/// Max words scanned per range in `find_arenas` (amplification guard).
const MAX_SCAN_WORDS: u64 = 1 << 28;

/// Confidence score at or above which an arena candidate is kept.
const ARENA_CONFIDENCE: u64 = 60;

/// A parsed chunk header.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// Address of the chunk header (`user - 0x10`).
    pub header: u64,
    /// Address of the user data (`header + 0x10`).
    pub user: u64,
    /// Raw `size` field as read from memory.
    pub size_field: u64,
    /// Usable size of the user region (`(size & !0xF) - 0x10`).
    pub user_size: u64,
    /// `true` if the previous chunk is in use (from the next chunk's flags).
    pub prev_in_use: bool,
    /// `true` if this chunk was served by `mmap`.
    pub is_mmapped: bool,
    /// `true` if this chunk belongs to a non-main arena.
    pub non_main_arena: bool,
}

/// Walks a heap region `[start, end)` and returns every valid chunk header.
///
/// The FIRST chunk header sits at the region start: `prev_size` at `start`,
/// `size` at `start + 8`, user data at `start + 0x10`. The walk stops (without
/// panic) at the first chunk whose size field is invalid, or when the
/// successor's header cannot be read (the current chunk is the top chunk).
pub fn walk_heap(image: &dyn AddressSpace, start: u64, end: u64) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    if end <= start || end - start < MIN_CHUNK_SIZE {
        return chunks;
    }
    let region_size = end - start;
    let max_iter = region_size / MIN_CHUNK_SIZE + 16;
    let mut cur = start;

    for _ in 0..max_iter {
        if chunks.len() >= MAX_OBJECTS {
            break;
        }
        let Some(size_field) = cur.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        let mask = size_field & !0xF;
        if mask < MIN_CHUNK_SIZE {
            break;
        }
        let Some(remaining) = end.checked_sub(cur) else {
            break;
        };
        if mask >= remaining {
            break;
        }
        let Some(next_header) = cur.checked_add(mask) else {
            break;
        };
        // The next chunk's PREV_INUSE bit describes the current chunk's state;
        // if we cannot read it, the current chunk is the top chunk.
        let Some(next_size) = next_header.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        let prev_in_use = next_size & PREV_INUSE != 0;
        chunks.push(Chunk {
            header: cur,
            user: cur + 0x10,
            size_field,
            user_size: mask - 0x10,
            prev_in_use,
            is_mmapped: size_field & IS_MMAPPED != 0,
            non_main_arena: size_field & NON_MAIN_ARENA != 0,
        });
        cur = next_header;
    }
    chunks
}

/// A scored arena candidate discovered during the file-backed scan.
struct ArenaCandidate {
    addr: u64,
    top: u64,
    is_main: bool,
}

/// Returns the arena's `top` pointer when it points into an anonymous rw-
/// heap region.
fn arena_top(image: &dyn AddressSpace, cand: u64) -> Option<u64> {
    let top = cand
        .checked_add(ARENA_TOP_OFFSET)
        .and_then(|p| image.read_word(p))?;
    let r = image.range_at(top)?;
    if matches!(r.kind, RangeKind::Anon | RangeKind::Unknown) && r.perms.write {
        Some(top)
    } else {
        None
    }
}

/// `true` if the chunk header at `top` (an mchunkptr, not the user pointer)
/// carries a plausible size that stays inside its containing range. The top
/// chunk's size is the remaining region bytes with `PREV_INUSE` set.
fn valid_top_header(image: &dyn AddressSpace, top: u64) -> bool {
    let Some(range) = image.range_at(top) else {
        return false;
    };
    let Some(size_field) = top.checked_add(8).and_then(|p| image.read_u64(p)) else {
        return false;
    };
    let mask = size_field & !0xF;
    mask >= MIN_CHUNK_SIZE && top.checked_add(mask).is_some_and(|t| t <= range.end)
}

/// Scores a candidate `malloc_state` at `cand`; returns it when confident.
///
/// The hard gates are: `top` points into an anonymous rw- region, the chunk
/// header at `top` is plausible, and the arena's `system_mem` field (offset
/// 0x888) is within a factor of the heap region size. Real heaps grown by
/// glibc keep `system_mem` roughly equal to the heap mapping size; libc data
/// words that merely happen to point into the heap fail that check.
fn evaluate_arena(image: &dyn AddressSpace, cand: u64) -> Option<ArenaCandidate> {
    let top = arena_top(image, cand)?;
    if !valid_top_header(image, top) {
        return None;
    }
    // `system_mem` must be plausible for the heap region `top` points into.
    let region_len = image.range_at(top).map_or(0, |r| r.len());
    let system_mem = cand
        .checked_add(ARENA_SYSTEM_MEM_OFFSET)
        .and_then(|p| image.read_word(p))
        .unwrap_or(0);
    // Scale the absolute cap with the heap region so multi-GB heaps keep
    // their arena, and use saturating arithmetic as defense in depth.
    let cap = 0x4000_0000u64.max(region_len.saturating_mul(16));
    if !(0x1000..=cap).contains(&system_mem)
        || region_len == 0
        || system_mem < region_len / 4
        || system_mem > region_len.saturating_mul(4)
    {
        return None;
    }

    let mut score: u64 = 40; // passed the hard gates (top+header+system_mem)
    if top.is_multiple_of(0x10) {
        score += 10;
    }
    // `main_arena` is a static in libc's data segment (file-backed); a thread
    // arena's malloc_state lives in its own anonymous heap. That is the
    // robust main-arena discriminator (the `next` self-loop disappears as
    // soon as a second arena exists).
    let is_main = image
        .range_at(cand)
        .is_some_and(|r| r.kind == RangeKind::File && r.perms.write);
    if let Some(next) = cand
        .checked_add(ARENA_NEXT_OFFSET)
        .and_then(|p| image.read_word(p))
    {
        if next == cand {
            score += 100;
        } else if next == 0 {
            score += 15;
        } else if image
            .range_at(next)
            .is_some_and(|r| r.kind == RangeKind::Anon && r.perms.write)
        {
            score += 25;
        } else if image
            .range_at(next)
            .is_some_and(|r| r.kind == RangeKind::File && r.perms.write)
        {
            score += 15;
        }
    }
    if cand.is_multiple_of(0x10) {
        score += 5;
    }
    if score < ARENA_CONFIDENCE {
        return None;
    }
    Some(ArenaCandidate {
        addr: cand,
        top,
        is_main,
    })
}

/// Size of the heap region the arena's `top` points into.
fn arena_region_size(image: &dyn AddressSpace, top: u64) -> u64 {
    image.range_at(top).map_or(0, |r| r.len())
}

/// Scans file-backed writable ranges for a `malloc_state` whose `top` field
/// points into an anonymous rw- heap, validating `main_arena` via its
/// self-looping `next` pointer. Never panics on garbage.
pub fn find_arenas(image: &dyn AddressSpace) -> Vec<ArenaInfo> {
    let mut arenas: Vec<ArenaInfo> = Vec::new();
    if image.pointer_width() != 8 {
        return arenas;
    }

    let mut candidates: Vec<ArenaCandidate> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    for range in image.map().writable_ranges() {
        if range.kind != RangeKind::File && range.kind != RangeKind::Unknown {
            continue;
        }
        // Align the scan start up to a word boundary without overflowing for
        // starts near u64::MAX (fall back to the range end, which then skips).
        let scan_start = range
            .start
            .checked_add(7)
            .map(|x| x & !7)
            .unwrap_or(range.end);
        // Only scan bytes physically present in the dump; a malicious range
        // claiming end == u64::MAX must not spin the loop forever.
        let scan_end = range
            .start
            .saturating_add(range.file_size)
            .min(range.end);
        // Cap the words scanned per range (amplification guard).
        let scan_end = scan_end.min(scan_start.saturating_add(MAX_SCAN_WORDS * 8));
        if scan_end <= scan_start {
            continue;
        }
        let mut p = scan_start;
        loop {
            if p >= scan_end {
                break;
            }
            let Some(next) = p.checked_add(8) else {
                break;
            };
            if next > range.end {
                break;
            }
            if let Some(top) = image.read_word(p) {
                if image
                    .range_at(top)
                    .is_some_and(|r| r.kind == RangeKind::Anon && r.perms.write)
                {
                    // The word at `p` is the arena's `top` field, so the
                    // `malloc_state` struct begins `ARENA_TOP_OFFSET` earlier.
                    if let Some(cand) = p.checked_sub(ARENA_TOP_OFFSET) {
                        if cand >= range.start && cand < range.end && seen.insert(cand) {
                            if let Some(ac) = evaluate_arena(image, cand) {
                                candidates.push(ac);
                            }
                        }
                    }
                }
            }
            p = next;
        }
    }

    for ac in &candidates {
        arenas.push(ArenaInfo {
            addr: ac.addr,
            size: arena_region_size(image, ac.top),
            top: ac.top,
            is_main: ac.is_main,
        });
    }

    // Follow `next` chains to pick up non-main arenas chained off confirmed
    // ones. Bounded so garbage chains cannot run away.
    let mut idx = 0;
    let mut guard = 0;
    while idx < candidates.len() && guard < 4096 {
        guard += 1;
        let cand = candidates[idx].addr;
        if let Some(next) = cand
            .checked_add(ARENA_NEXT_OFFSET)
            .and_then(|p| image.read_word(p))
        {
            if next != cand {
                let plausible = image
                    .range_at(next)
                    .is_some_and(|r| r.perms.write && (r.kind == RangeKind::Anon || r.kind == RangeKind::File));
                if plausible && seen.insert(next) {
                    if let Some(ac) = evaluate_arena(image, next) {
                        arenas.push(ArenaInfo {
                            addr: ac.addr,
                            size: arena_region_size(image, ac.top),
                            top: ac.top,
                            is_main: false,
                        });
                        candidates.push(ac);
                    }
                }
            }
        }
        idx += 1;
    }

    // Non-main arenas: a thread's arena heap is a standalone anonymous mapping
    // that begins with a `heap_info` header whose `ar_ptr` points at the
    // arena's `malloc_state` (also in the region). `find_arenas` scans
    // file-backed ranges above, so an arena whose state lives in an anon heap
    // (common once a thread has exited and glibc dropped it from the `next`
    // chain) is only discoverable by validating this anon signature. The
    // `ar_ptr -> top-into-same-region -> plausible system_mem` gates make
    // false positives very unlikely (stacks and mmap buffers do not start
    // with an in-region `malloc_state` pointer).
    for region in image.map().writable_ranges() {
        if region.len() < PAGE_SIZE || !matches!(region.kind, RangeKind::Anon | RangeKind::Unknown) {
            continue;
        }
        let Some(ar_ptr) = image.read_word(region.start) else {
            continue;
        };
        // glibc places the arena's malloc_state right after the 0x20-byte
        // `heap_info`, so `ar_ptr - region.start` is a small offset (0x20..0x100).
        // Requiring that shape rejects stack frames and arbitrary anon buffers
        // whose first word happens to be an in-region pointer.
        let off = match ar_ptr.checked_sub(region.start) {
            Some(o) if (0x20..0x100).contains(&o) => o,
            _ => continue,
        };
        let _ = off;
        if let Some(ac) = evaluate_arena(image, ar_ptr) {
            if seen.insert(ar_ptr) {
                arenas.push(ArenaInfo {
                    addr: ac.addr,
                    size: arena_region_size(image, ac.top),
                    top: ac.top,
                    is_main: false,
                });
            }
        }
    }

    arenas.sort_by_key(|a| a.addr);
    arenas.dedup_by(|a, b| a.addr == b.addr);
    arenas
}

/// Probes candidate first-chunk offsets within a region and walks from the
/// first one that yields any valid chunk.
///
/// The main heap (`main_arena`) starts its first chunk header at the region
/// start (offset 0). Non-main arenas' heaps begin with a `heap_info` header
/// (32 bytes on 64-bit), so the first chunk header sits at a small positive
/// offset. Walking from offset 0 would read `heap_info` as a chunk header,
/// get garbage, and yield zero objects — silently. This probes a small set of
/// aligned offsets within the first page and uses the first that recovers at
/// least one chunk.
/// Walks a heap region by probing a small set of plausible first-chunk
/// Counts chunks recoverable from `start`, stopping after `cap` chunks. Used
/// by [`probe_walk_region`] to rank candidate first-chunk offsets cheaply
/// without walking an entire (potentially huge) region once per probe.
fn count_chunks_capped(image: &dyn AddressSpace, start: u64, end: u64, cap: usize) -> usize {
    let mut cur = start;
    let mut count = 0usize;
    for _ in 0..cap {
        let Some(size_field) = cur.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        let mask = size_field & !0xF;
        if mask < MIN_CHUNK_SIZE || mask >= end.saturating_sub(cur) {
            break;
        }
        let Some(next) = cur.checked_add(mask) else {
            break;
        };
        let Some(_next_size) = next.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        count += 1;
        cur = next;
    }
    count
}

/// Walks a heap region by probing a small set of plausible first-chunk
/// offsets and returning the objects carved from the best offset.
///
/// Real glibc main-arena heaps start their first chunk at the region base,
/// but non-main arenas begin with a `heap_info` header, so the first chunk
/// may sit 0x20..0x100 bytes in. Probing is two-phase: each offset gets a
/// CHEAP capped count (bounded, so a crafted huge region cannot be walked
/// once per probe), then a single full walk runs from the winning offset.
/// `min_chunks` is 1 for a self-looping `main_arena` and 3 otherwise (the
/// same evidence bar as [`chunk_chain_plausible`]).
fn probe_walk_region(
    image: &dyn AddressSpace,
    region: &MemoryRange,
    arena: Option<u64>,
    min_chunks: usize,
    prefer_offset0: bool,
) -> Vec<Object> {
    const COUNT_CAP: usize = 256; // enough to rank offsets without full walks

    // Candidate first-chunk offsets: fixed small ones, offsets relative to the
    // known arena address (non-main arenas put the malloc_state ~0x898 bytes
    // in), and a dense grid over the first 4 KiB.
    let mut probe_offsets: Vec<u64> = vec![0x0, 0x10, 0x20, 0x30, 0x40, 0x80];
    let arena_anchor: Option<u64> = if let Some(ar) = arena {
        if ar >= region.start {
            let base = ar - region.start;
            for delta in [0x880u64, 0x890, 0x898, 0x8a0, 0x8b0, 0x8c0, 0x8d0, 0x900] {
                probe_offsets.push(base.saturating_add(delta));
            }
            Some(base.saturating_add(0x8d0))
        } else {
            None
        }
    } else {
        None
    };
    let mut off = 0x100u64;
    while off < 0x1000 {
        probe_offsets.push(off);
        off += 0x20;
    }

    // Phase 1: cheap capped counts for every offset.
    let mut ranked: Vec<(u64, usize)> = Vec::new();
    for &off in &probe_offsets {
        let Some(start) = region.start.checked_add(off) else {
            continue;
        };
        if start >= region.end {
            continue;
        }
        let count = count_chunks_capped(image, start, region.end, COUNT_CAP);
        if count >= min_chunks {
            ranked.push((off, count));
        }
    }
    if ranked.is_empty() {
        return Vec::new();
    }

    // Phase 2: pick the winner. Prefer the main-arena anchor (offset 0) or
    // the arena-relative anchor (thread arenas) when it clears the bar, and
    // only let a challenger displace an anchor on a DECISIVE margin (>= 2x)
    // so a dense array of chunk-lookalike words inside the first page cannot
    // steal the walk.
    let anchor = if prefer_offset0 { Some(0x0u64) } else { arena_anchor };
    let best_off = match anchor {
        Some(a) => match ranked.iter().find(|(o, _)| *o == a) {
            Some(&(_, anchor_count)) => {
                // Keep the anchor unless a challenger decisively beats it.
                let challenger = ranked
                    .iter()
                    .filter(|(o, _)| *o != a)
                    .filter(|(_, c)| *c >= anchor_count.saturating_mul(2))
                    .max_by_key(|(_, c)| *c);
                challenger.map(|(o, _)| *o).unwrap_or(a)
            }
            None => ranked.iter().max_by_key(|(_, c)| *c).expect("ranked non-empty").0,
        },
        None => ranked.iter().max_by_key(|(_, c)| *c).expect("ranked non-empty").0,
    };

    let start = region.start.checked_add(best_off).unwrap_or(region.start);
    walk_heap(image, start, region.end)
        .into_iter()
        .map(|c| {
            let (state, freed_reason) = if c.is_mmapped {
                (ObjectState::Mmap, None)
            } else if c.prev_in_use {
                (ObjectState::Allocated, None)
            } else {
                (ObjectState::Freed, Some(crate::FreedReason::PrevInuseClear))
            };
            Object {
                addr: c.user,
                size: c.user_size,
                state,
                arena,
                chunk_header: c.header,
                freed_reason,
            }
        })
        .collect()
}

/// Converts a region's chunks into carved objects.
fn collect_objects(
    image: &dyn AddressSpace,
    region: &MemoryRange,
    arena: Option<u64>,
    min_chunks: usize,
    prefer_offset0: bool,
) -> Vec<Object> {
    probe_walk_region(image, region, arena, min_chunks, prefer_offset0)
}

/// glibc safe-linking unmangle: a stored pointer `v` at slot address `pos`
/// was mangled as `(pos >> 12) ^ ptr`; reveal the original pointer. Used to
/// decode a freed chunk's `fd`/`bk` free-list linkage. Kept for future
/// free-list decoding.
fn reveal_safe_link(pos: u64, v: u64) -> u64 {
    (pos >> 12) ^ v
}

/// Marks chunks freed into glibc's per-thread tcache as [`Freed`].
///
/// tcache'd chunks do NOT clear the successor's `PREV_INUSE` bit (that only
/// happens for bin/unsorted consolidation), so the chunk-header heuristic
/// reports them as allocated. The `tcache_perthread_struct` keeps the
/// per-size-class free lists; its `entries[]` hold the PLAIN user pointers of
/// the freed chunks (only the intra-list `fd` links inside each freed chunk
/// are safe-link mangled), so any carved object whose address appears there is
/// a freed chunk.
fn mark_tcache_freed(image: &dyn AddressSpace, objects: &mut [Object]) {
    const MAX_CHAIN: usize = 16; // TCACHE_FILL_COUNT is 7
    // Global step budget so a crafted dump full of tcache-lookalike objects
    // cannot stall carving (each candidate would otherwise cost up to
    // 64 bins * 16 chain steps).
    const MAX_STEPS: usize = 4096;
    let by_addr: HashMap<u64, usize> = objects
        .iter()
        .enumerate()
        .map(|(i, o)| (o.addr, i))
        .collect();
    let mut freed: Vec<usize> = Vec::new();
    let mut steps = 0usize;
    for obj in objects.iter() {
        if steps >= MAX_STEPS {
            break;
        }
        if obj.state != ObjectState::Allocated || obj.size < 0x280 {
            continue;
        }
        // tcache_perthread_struct: u16 counts[64] at +0, entries[64] at +0x80.
        let mut counts = [0u16; 64];
        let counts_ok = (0..64).all(|i| {
            let c = image.read_u16(obj.addr + i as u64 * 2);
            if let Some(c) = c {
                counts[i] = c;
            }
            c.is_some_and(|v| v < 0x40)
        });
        if !counts_ok {
            continue;
        }
        for (i, &count) in counts.iter().enumerate() {
            if steps >= MAX_STEPS {
                break;
            }
            // glibc invariant: entries[i] != NULL  <=>  counts[i] > 0.
            if count == 0 {
                continue;
            }
            let slot = obj.addr + 0x80 + i as u64 * 8;
            let Some(mut cur) = image.read_u64(slot) else {
                continue;
            };
            if cur == 0 {
                continue;
            }
            // `entries[i]` is the PLAIN user pointer of the bin head; the rest
            // of the chain is safe-link mangled in each freed chunk's `fd`
            // (`(chunk_user >> 12) ^ next`), so walk it with reveal. Abort the
            // bin as soon as a link does not resolve to a carved object: a
            // corrupt chain (or a false tcache-lookalike) must not mark
            // unrelated objects freed.
            let chain_max = (count as usize).min(MAX_CHAIN);
            for _ in 0..chain_max {
                steps += 1;
                if cur == 0 {
                    break;
                }
                let Some(&idx) = by_addr.get(&cur) else {
                    break;
                };
                freed.push(idx);
                let Some(fd) = image.read_word(cur) else {
                    break;
                };
                if fd == 0 {
                    break;
                }
                cur = reveal_safe_link(cur, fd);
            }
        }
    }
    for idx in freed {
        objects[idx].state = ObjectState::Freed;
        objects[idx].freed_reason = Some(crate::FreedReason::Tcache);
    }
}

/// Marks chunks freed into glibc's arena fastbins as [`Freed`].
///
/// Fastbin-freed chunks (like tcache ones) keep the successor's `PREV_INUSE`
/// set, so the chunk-header heuristic reports them as allocated. The arena's
/// `fastbinsY[0..10]` holds the CHUNK-HEADER address of each bin head; each
/// freed chunk stores its `fd` link (safe-link MANGLED since glibc 2.32) at
/// its user address. Walking those chains (revealing each link, then adding
/// 0x10 to map header -> user before the address lookup) marks the referenced
/// chunks freed.
fn mark_fastbin_freed(image: &dyn AddressSpace, arena: u64, objects: &mut [Object]) {
    const FASTBINS_Y_OFFSET: u64 = 0x10;
    const FASTBIN_COUNT: usize = 10;
    const MAX_CHAIN: usize = 64;
    let by_addr: HashMap<u64, usize> = objects
        .iter()
        .enumerate()
        .map(|(i, o)| (o.addr, i))
        .collect();
    let mut freed: Vec<usize> = Vec::new();
    for bin in 0..FASTBIN_COUNT {
        let Some(head) = arena
            .checked_add(FASTBINS_Y_OFFSET + bin as u64 * 8)
            .and_then(|p| image.read_word(p))
        else {
            continue;
        };
        // Bin heads are chunk-header addresses; an empty bin self-references
        // the bin slot itself (in the arena), which resolves to nothing.
        let mut cur_header = head;
        for _ in 0..MAX_CHAIN {
            if cur_header == 0 {
                break;
            }
            let Some(user) = cur_header.checked_add(0x10) else {
                break;
            };
            let Some(&idx) = by_addr.get(&user) else {
                // Link points outside the carved heap (e.g. an empty bin's
                // self-referential head): stop following it.
                break;
            };
            freed.push(idx);
            // The next link is the mangled `fd` stored at the chunk's user
            // address (slot address == user).
            let Some(fd) = image.read_word(user) else {
                break;
            };
            if fd == 0 {
                break;
            }
            cur_header = reveal_safe_link(user, fd);
        }
    }
    for idx in freed {
        objects[idx].state = ObjectState::Freed;
        objects[idx].freed_reason = Some(crate::FreedReason::Fastbin);
    }
}

/// Carves a standalone `mmap`-served allocation out of an anonymous rw-
/// region. glibc places the chunk header at the mapping start with
/// `IS_MMAPPED` set in the size field. Returns `None` if the region does not
/// start with a plausible mmapped chunk.
fn carve_mmap_region(image: &dyn AddressSpace, region: &MemoryRange) -> Option<Object> {
    // A real glibc mmap chunk satisfies four invariants: prev_size == 0,
    // IS_MMAPPED set, PREV_INUSE clear (glibc only sets the M bit), and a
    // page-aligned chunk size. Requiring all of them rejects stacks and
    // arbitrary anon buffers whose first words merely look pointer-ish.
    let prev_size = image.read_u64(region.start)?;
    let size_field = region.start.checked_add(8).and_then(|p| image.read_u64(p))?;
    if prev_size != 0
        || size_field & IS_MMAPPED == 0
        || size_field & PREV_INUSE != 0
    {
        return None;
    }
    let mask = size_field & !0xF;
    if mask < PAGE_SIZE || mask > region.len() || mask % PAGE_SIZE != 0 {
        return None;
    }
    Some(Object {
        addr: region.start + 0x10,
        size: mask - 0x10,
        state: ObjectState::Mmap,
        arena: None,
        chunk_header: region.start,
        freed_reason: None,
    })
}

/// Bounded plausibility check that a region starts with at least 3 recoverable
/// chunk headers. Never panics; at most 64 chunk headers are examined so a
/// garbage region cannot cause unbounded work.
fn chunk_chain_plausible(image: &dyn AddressSpace, start: u64, end: u64) -> bool {
    const MAX_CHECKS: usize = 64;
    if end <= start || end - start < MIN_CHUNK_SIZE {
        return false;
    }
    let mut cur = start;
    let mut valid = 0usize;
    for _ in 0..MAX_CHECKS {
        if cur >= end {
            break;
        }
        let Some(size_field) = cur.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        let mask = size_field & !0xF;
        if mask < MIN_CHUNK_SIZE {
            break;
        }
        let Some(next) = cur.checked_add(mask) else {
            break;
        };
        if next >= end {
            break;
        }
        let Some(_next_size) = next.checked_add(8).and_then(|p| image.read_u64(p)) else {
            break;
        };
        valid += 1;
        if valid >= 3 {
            return true;
        }
        cur = next;
    }
    false
}

/// Carves heap objects out of `image`.
///
/// Walks the anonymous rw- region containing each discovered arena's `top`.
/// When no arena is found (e.g. a symbol-less dump), falls back to walking
/// anonymous writable regions of at least one page that pass a chunk-chain
/// plausibility check. Stacks and other non-heap anon regions are never carved
/// while arenas are present. Objects are deduplicated by address, sorted, and
/// capped at [`MAX_OBJECTS`].
pub fn carve(image: &dyn AddressSpace) -> HeapInventory {
    let mut inventory = HeapInventory::default();
    if image.pointer_width() != 8 {
        return inventory;
    }

    inventory.arenas = find_arenas(image);

    let mut walked: HashSet<u64> = HashSet::new();
    let mut objects: Vec<Object> = Vec::new();

    let mut carve_region =
        |region: &MemoryRange, arena: Option<u64>, min_chunks: usize, is_main: bool| {
        if !walked.insert(region.start) {
            return;
        }
        let mut region_objects = collect_objects(image, region, arena, min_chunks, is_main);
        // Bound the object count DURING carving (not only at the end) so a
        // dump with many plausible regions cannot accumulate N * MAX_OBJECTS
        // objects (and matching tcache/fastbin HashMaps) in memory.
        region_objects.truncate(MAX_OBJECTS.saturating_sub(objects.len()));
        if region_objects.is_empty() {
            return;
        }
        mark_tcache_freed(image, &mut region_objects);
        if let Some(a) = arena {
            mark_fastbin_freed(image, a, &mut region_objects);
        }
        objects.extend(region_objects);
    };

    for arena in &inventory.arenas {
        if let Some(region) = image.range_at(arena.top) {
            if matches!(region.kind, RangeKind::Anon | RangeKind::Unknown)
                && region.perms.write
            {
                // A self-looping main_arena is strong evidence by itself, so
                // accept a single chunk; every other arena path must clear the
                // same 3-chunk bar as the arena-less fallback so stack-like
                // garbage is not carved.
                let min_chunks = if arena.is_main { 1 } else { 3 };
                carve_region(region, Some(arena.addr), min_chunks, arena.is_main);
            }
        }
    }

    if inventory.arenas.is_empty() {
        for region in image.map().anon_ranges() {
            if region.perms.write
                && region.len() >= PAGE_SIZE
                && chunk_chain_plausible(image, region.start, region.end)
            {
                carve_region(region, None, 3, true);
            }
        }
    }

    // Standalone mmap-served allocations in anonymous rw- regions that were
    // not walked as arenas (glibc serves large requests via mmap).
    for region in image.map().writable_ranges() {
        if !matches!(region.kind, RangeKind::Anon | RangeKind::Unknown) {
            continue;
        }
        if region.len() >= PAGE_SIZE && !walked.contains(&region.start) {
            if let Some(obj) = carve_mmap_region(image, region) {
                walked.insert(region.start);
                objects.push(obj);
            }
        }
    }

    objects.sort_by_key(|o| o.addr);
    objects.dedup_by(|a, b| a.addr == b.addr);
    objects.truncate(MAX_OBJECTS);
    inventory.objects = objects;
    inventory
}

#[cfg(test)]
mod tests {
    use super::*;
    use naksheap_core_parse::{MappedImage, MemoryMap, Perms};

    struct ImageBuilder {
        bytes: Vec<u8>,
        ranges: Vec<MemoryRange>,
    }

    impl ImageBuilder {
        fn new() -> Self {
            ImageBuilder {
                bytes: Vec::new(),
                ranges: Vec::new(),
            }
        }

        fn add_range(&mut self, start: u64, len: u64, kind: RangeKind, perms: Perms) {
            let off = self.bytes.len() as u64;
            self.bytes.resize(off as usize + len as usize, 0);
            self.ranges.push(MemoryRange {
                start,
                end: start + len,
                file_offset: off,
                file_size: len,
                perms,
                kind,
                path: None,
                name: None,
            });
        }

        fn write(&mut self, addr: u64, data: &[u8]) {
            let r = self
                .ranges
                .iter()
                .find(|r| r.contains(addr))
                .unwrap_or_else(|| panic!("addr {addr:#x} unmapped"));
            let delta = addr - r.start;
            assert!(
                delta + data.len() as u64 <= r.file_size,
                "write out of range at {addr:#x}"
            );
            let base = (r.file_offset + delta) as usize;
            self.bytes[base..base + data.len()].copy_from_slice(data);
        }

        fn write_u64(&mut self, addr: u64, v: u64) {
            self.write(addr, &v.to_le_bytes());
        }

        fn build(self) -> MappedImage {
            MappedImage::from_bytes(self.bytes, MemoryMap::from_ranges(self.ranges), 8)
        }
    }

    fn add_heap(b: &mut ImageBuilder, start: u64, len: u64) {
        b.add_range(
            start,
            len,
            RangeKind::Anon,
            Perms {
                read: true,
                write: true,
                execute: false,
            },
        );
    }

    fn add_libc(b: &mut ImageBuilder, start: u64, len: u64) {
        b.add_range(
            start,
            len,
            RangeKind::File,
            Perms {
                read: true,
                write: true,
                execute: false,
            },
        );
    }

    /// Writes a chunk with the given header address and user-region size.
    fn place_chunk(b: &mut ImageBuilder, header: u64, user_size: u64, flags: u64, fill: u8) {
        let mask = (0x10 + user_size + 0xF) & !0xF;
        b.write_u64(header + 8, mask | flags);
        if user_size > 0 {
            b.write(header + 0x10, &vec![fill; user_size as usize]);
        }
    }

    /// Writes a top chunk filling the rest of its region.
    fn place_top(b: &mut ImageBuilder, header: u64, region_end: u64) {
        b.write_u64(header + 8, (region_end - header) | PREV_INUSE);
    }

    const H: u64 = 0x7f00_0000_0000;
    const H_END: u64 = H + 0x2000;

    fn base_heap(b: &mut ImageBuilder) {
        add_heap(b, H, H_END - H);
    }

    #[test]
    fn walk_heap_allocated_chunks_and_top() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b);
        place_chunk(&mut b, H, 0x20, PREV_INUSE, 0x41); // user H+0x10
        place_chunk(&mut b, H + 0x30, 0x40, PREV_INUSE, 0x42); // user H+0x40
        place_chunk(&mut b, H + 0x80, 0x30, PREV_INUSE, 0x43); // user H+0x90
        place_top(&mut b, H + 0xc0, H_END);

        let img = b.build();
        let chunks = walk_heap(&img, H, H_END);
        assert_eq!(chunks.len(), 3);

        assert_eq!(chunks[0].header, H);
        assert_eq!(chunks[0].user, H + 0x10);
        assert_eq!(chunks[0].user_size, 0x20);
        assert!(chunks[0].prev_in_use);
        assert!(!chunks[0].is_mmapped);
        assert!(!chunks[0].non_main_arena);

        assert_eq!(chunks[1].header, H + 0x30);
        assert_eq!(chunks[1].user, H + 0x40);
        assert_eq!(chunks[1].user_size, 0x40);

        assert_eq!(chunks[2].header, H + 0x80);
        assert_eq!(chunks[2].user, H + 0x90);
        assert_eq!(chunks[2].user_size, 0x30);

        // carve() must surface the same objects, Allocated, no top chunk.
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 3);
        assert!(inv.objects.iter().all(|o| o.state == ObjectState::Allocated));
        assert_eq!(inv.objects[0].addr, H + 0x10);
        assert_eq!(inv.objects[0].size, 0x20);
        assert_eq!(inv.objects[1].addr, H + 0x40);
        assert_eq!(inv.objects[1].size, 0x40);
        assert_eq!(inv.objects[2].addr, H + 0x90);
        assert_eq!(inv.objects[2].size, 0x30);
    }

    #[test]
    fn walk_heap_freed_chunk() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b);
        place_chunk(&mut b, H, 0x30, PREV_INUSE, 0x41); // user H+0x10
        // Next chunk's PREV_INUSE clear => chunk[0] is freed.
        place_chunk(&mut b, H + 0x40, 0x20, 0, 0x42); // user H+0x50
        place_chunk(&mut b, H + 0x70, 0x20, PREV_INUSE, 0x43); // user H+0x80
        place_top(&mut b, H + 0xa0, H_END);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 3);
        assert_eq!(inv.objects[0].addr, H + 0x10);
        assert_eq!(inv.objects[0].state, ObjectState::Freed);
        assert_eq!(inv.objects[1].addr, H + 0x50);
        assert_eq!(inv.objects[1].state, ObjectState::Allocated);
        assert_eq!(inv.objects[2].addr, H + 0x80);
        assert_eq!(inv.objects[2].state, ObjectState::Allocated);
    }

    #[test]
    fn walk_heap_garbage_stops_gracefully() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b);
        place_chunk(&mut b, H, 0x30, PREV_INUSE, 0x41); // user H+0x10
        place_chunk(&mut b, H + 0x40, 0x20, PREV_INUSE, 0x42); // user H+0x50
        // Garbage size field that exceeds the region (PREV_INUSE set so the
        // preceding chunk still reads as Allocated).
        b.write_u64(H + 0x70 + 8, 0xDEAD_BEEF_0000_0001);
        // Out-of-bounds read after the garbage must not panic.
        let img = b.build();
        let chunks = walk_heap(&img, H, H_END);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].user, H + 0x10);
        assert!(chunks[0].prev_in_use);
        assert_eq!(chunks[1].user, H + 0x50);
        assert!(chunks[1].prev_in_use);
    }

    #[test]
    fn walk_heap_undersized_size_stops_gracefully() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b);
        place_chunk(&mut b, H, 0x30, PREV_INUSE, 0x41);
        // An undersized (< 0x20) chunk size should stop the walk, not panic.
        b.write_u64(H + 0x40 + 8, 0x5);
        let img = b.build();
        let chunks = walk_heap(&img, H, H_END);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].user, H + 0x10);
        assert!(chunks[0].prev_in_use);
    }

    #[test]
    fn walk_heap_mmapped_chunk() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b);
        place_chunk(&mut b, H, 0x20, PREV_INUSE, 0x41); // user H+0x10
        place_chunk(&mut b, H + 0x30, 0x30, PREV_INUSE | IS_MMAPPED, 0x42); // user H+0x40
        place_chunk(&mut b, H + 0x70, 0x20, PREV_INUSE, 0x43); // user H+0x80
        place_top(&mut b, H + 0xa0, H_END);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 3);
        assert_eq!(inv.objects[0].state, ObjectState::Allocated);
        assert_eq!(inv.objects[1].addr, H + 0x40);
        assert_eq!(inv.objects[1].state, ObjectState::Mmap);
        assert_eq!(inv.objects[2].state, ObjectState::Allocated);
    }

    #[test]
    fn find_arenas_locates_main_arena() {
        const L: u64 = 0x7faa_0000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, 0x1000);

        let arena = L + 0x100;
        let top = H + 0x40; // main_arena.top points at the TOP CHUNK HEADER.
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_NEXT_OFFSET, arena);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, 0x1000);

        // Realistic heap: first chunk header at region start, then a top
        // chunk whose header `main_arena.top` points at.
        place_chunk(&mut b, H, 0x30, PREV_INUSE, 0x41);
        place_top(&mut b, H + 0x40, H + 0x1000);

        let img = b.build();
        let arenas = find_arenas(&img);
        assert_eq!(arenas.len(), 1);
        assert_eq!(arenas[0].addr, arena);
        assert_eq!(arenas[0].top, top);
        assert_eq!(arenas[0].size, 0x1000);
        assert!(arenas[0].is_main);

        let inv = crate::carve(&img);
        assert_eq!(inv.arenas.len(), 1);
        assert_eq!(inv.objects.len(), 1);
        assert_eq!(inv.objects[0].addr, H + 0x10);
        assert_eq!(inv.objects[0].arena, Some(arena));
    }

    #[test]
    fn find_arenas_ignores_garbage() {
        const L: u64 = 0x7faa_0000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, 0x2000);

        // A pointer into the heap that is NOT a real arena: no self-loop, and
        // no plausible top-header at +0x60. Must not produce an arena.
        let fake = L + 0x40;
        b.write_u64(fake + ARENA_TOP_OFFSET, H + 0x1000);
        b.write_u64(fake + ARENA_NEXT_OFFSET, L + 0x40 + 8);

        let img = b.build();
        assert!(find_arenas(&img).is_empty());
    }

    #[test]
    fn carve_dedups_and_sorts() {
        let mut b = ImageBuilder::new();
        // Two heap regions with no arenas present; carve reaches them via the
        // chunk-chain plausibility fallback. Each region carries 3 chunks plus
        // a top chunk so the fallback accepts it.
        add_heap(&mut b, H, H_END - H);
        add_heap(&mut b, H_END + 0x1000, 0x2000);

        place_chunk(&mut b, H, 0x20, PREV_INUSE, 0x41);
        place_chunk(&mut b, H + 0x30, 0x20, PREV_INUSE, 0x42);
        place_chunk(&mut b, H + 0x60, 0x20, PREV_INUSE, 0x43);
        place_top(&mut b, H + 0x90, H_END);
        place_chunk(&mut b, H_END + 0x1000, 0x20, PREV_INUSE, 0x51);
        place_chunk(&mut b, H_END + 0x1030, 0x20, PREV_INUSE, 0x52);
        place_chunk(&mut b, H_END + 0x1060, 0x20, PREV_INUSE, 0x53);
        place_top(&mut b, H_END + 0x1090, H_END + 0x3000);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 6);
        assert!(inv.objects.windows(2).all(|w| w[0].addr < w[1].addr));
    }

    #[test]
    fn carve_with_arena_skips_stack() {
        // When an arena is present, only the anon rw- region containing the
        // arena's `top` is carved; a stack region full of chunk-lookalikes
        // must NOT produce objects.
        const L: u64 = 0x7faa_0000_0000;
        const S: u64 = 0x7fff_0000_0000;
        const S_END: u64 = S + 0x4000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, H_END - H);
        add_heap(&mut b, S, S_END - S);

        let arena = L + 0x100;
        let top = H + 0x90; // top chunk header
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_NEXT_OFFSET, arena);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, H_END - H);

        // Heap: three chunks plus a top chunk.
        place_chunk(&mut b, H, 0x20, PREV_INUSE, 0x41);
        place_chunk(&mut b, H + 0x30, 0x20, PREV_INUSE, 0x42);
        place_chunk(&mut b, H + 0x60, 0x20, PREV_INUSE, 0x43);
        place_top(&mut b, H + 0x90, H_END);

        // Stack region that would pass the chunk-chain plausibility fallback
        // if it were ever walked.
        place_chunk(&mut b, S, 0x20, PREV_INUSE, 0x71);
        place_chunk(&mut b, S + 0x30, 0x20, PREV_INUSE, 0x72);
        place_chunk(&mut b, S + 0x60, 0x20, PREV_INUSE, 0x73);
        place_top(&mut b, S + 0x90, S_END);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.arenas.len(), 1);
        assert_eq!(inv.objects.len(), 3);
        assert!(
            inv.objects.iter().all(|o| o.addr >= H && o.addr < H_END),
            "carve with a known arena must not carve non-heap regions"
        );
    }

    #[test]
    fn find_arenas_terminates_on_max_end() {
        // A malicious file-backed range claiming end == u64::MAX (or starting
        // right before u64::MAX) must not make the scan wrap and spin forever.
        // The test passing within normal time is the assertion.
        let mut ranges = vec![MemoryRange {
            start: 0x7faa_0000_0000,
            end: u64::MAX,
            file_offset: 0,
            file_size: 0x1000,
            perms: Perms {
                read: true,
                write: true,
                execute: false,
            },
            kind: RangeKind::File,
            path: None,
            name: None,
        }];
        ranges.push(MemoryRange {
            start: u64::MAX - 0x4,
            end: u64::MAX,
            file_offset: 0x1000,
            file_size: 0x10,
            perms: Perms {
                read: true,
                write: true,
                execute: false,
            },
            kind: RangeKind::File,
            path: None,
            name: None,
        });
        let bytes = vec![0u8; 0x2000];
        let img = MappedImage::from_bytes(bytes, MemoryMap::from_ranges(ranges), 8);
        let arenas = find_arenas(&img);
        assert!(arenas.is_empty());
    }

    #[test]
    fn walk_heap_excludes_top_chunk_consuming_entire_region() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b); // H..H_END
        // Adjacent mapped range right after the heap: without the `>=` guard
        // a walk would read the "next chunk" size at H_END+8 successfully and
        // emit the top chunk as a spurious Allocated object.
        add_heap(&mut b, H_END, 0x1000);
        b.write_u64(H_END + 8, 0x30 | PREV_INUSE);

        place_chunk(&mut b, H, 0x20, PREV_INUSE, 0x41); // user H+0x10
        place_chunk(&mut b, H + 0x30, 0x20, PREV_INUSE, 0x42); // user H+0x40
        place_chunk(&mut b, H + 0x60, 0x20, PREV_INUSE, 0x43); // user H+0x70
        // The top chunk consumes exactly the remaining bytes of the region.
        place_top(&mut b, H + 0x90, H_END);

        let img = b.build();
        let chunks = walk_heap(&img, H, H_END);
        assert_eq!(chunks.len(), 3);
        assert!(chunks.iter().all(|c| c.header != H + 0x90));
        assert_eq!(chunks[0].header, H);
        assert_eq!(chunks[1].header, H + 0x30);
        assert_eq!(chunks[2].header, H + 0x60);

        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 3);
        assert_eq!(inv.objects[0].addr, H + 0x10);
        assert_eq!(inv.objects[1].addr, H + 0x40);
        assert_eq!(inv.objects[2].addr, H + 0x70);
    }

    #[test]
    fn probe_walk_region_skips_heap_info_header() {
        let mut b = ImageBuilder::new();
        base_heap(&mut b); // H..H_END
        // heap_info-shaped 0x20-byte header: ar_ptr, prev, size,
        // mprotect_size. Walking from offset 0 reads `prev` as the chunk size
        // (0) and yields nothing; the probe must start at H+0x20.
        b.write_u64(H, 0x7faa_0000_0100);
        b.write_u64(H + 0x08, 0);
        b.write_u64(H + 0x10, H_END - H);
        b.write_u64(H + 0x18, H_END - H);

        place_chunk(&mut b, H + 0x20, 0x20, PREV_INUSE, 0x41); // user H+0x30
        place_chunk(&mut b, H + 0x50, 0x20, PREV_INUSE, 0x42); // user H+0x60
        place_chunk(&mut b, H + 0x80, 0x20, PREV_INUSE, 0x43); // user H+0x90
        place_top(&mut b, H + 0xb0, H_END);

        let img = b.build();
        let region = img.range_at(H).unwrap();
        let objs = probe_walk_region(&img, region, Some(0x7faa_0000_0100), 3, false);
        assert_eq!(objs.len(), 3);
        assert_eq!(objs[0].addr, H + 0x30);
        assert_eq!(objs[0].arena, Some(0x7faa_0000_0100));
        assert_eq!(objs[1].addr, H + 0x60);
        assert_eq!(objs[2].addr, H + 0x90);
        assert!(objs.iter().all(|o| o.state == ObjectState::Allocated));
    }

    #[test]
    fn carve_non_main_arena_walks_past_heap_info() {
        const L: u64 = 0x7faa_0000_0000;
        // A thread arena: its malloc_state lives in an ANON region (not libc
        // data), which is how naksheap distinguishes non-main arenas.
        const A: u64 = 0x7faa_1000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, H_END - H);
        add_heap(&mut b, A, 0x1000);

        // malloc_state sits right after the 0x20-byte heap_info (real layout).
        let arena = A + 0x30;
        let top = H + 0xb0; // top chunk header
        // heap_info at the region start: ar_ptr -> the malloc_state in-region.
        b.write_u64(A, arena);
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, H_END - H);
        // Non-main arena: `next` points at another anon rw region, no self-loop.
        b.write_u64(arena + ARENA_NEXT_OFFSET, H + 0x100);

        // heap_info-shaped blob at the region start.
        b.write_u64(H, L + 0x100);
        b.write_u64(H + 0x08, 0);
        b.write_u64(H + 0x10, H_END - H);
        b.write_u64(H + 0x18, H_END - H);

        place_chunk(&mut b, H + 0x20, 0x20, PREV_INUSE, 0x41); // user H+0x30
        place_chunk(&mut b, H + 0x50, 0x20, PREV_INUSE, 0x42); // user H+0x60
        place_chunk(&mut b, H + 0x80, 0x20, PREV_INUSE, 0x43); // user H+0x90
        place_top(&mut b, H + 0xb0, H_END);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.arenas.len(), 1);
        assert!(!inv.arenas[0].is_main);
        assert_eq!(inv.objects.len(), 3);
        assert_eq!(inv.objects[0].addr, H + 0x30);
        assert_eq!(inv.objects[1].addr, H + 0x60);
        assert_eq!(inv.objects[2].addr, H + 0x90);
    }

    #[test]
    fn find_arenas_discovers_arena_with_null_next() {
        const L: u64 = 0x7faa_0000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, 0x1000);

        let arena = L + 0x100;
        let top = H + 0x40; // top chunk header
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, 0x1000);
        // No self-loop: `next` reads as NULL. The +15 bonus plus a valid top
        // header and plausible system_mem must clear the confidence threshold.
        // The malloc_state sits in libc's file-backed data, so it is the main
        // arena (main_arena is a static in libc .data).
        b.write_u64(arena + ARENA_NEXT_OFFSET, 0);

        place_chunk(&mut b, H, 0x30, PREV_INUSE, 0x41);
        place_top(&mut b, H + 0x40, H + 0x1000);

        let img = b.build();
        let arenas = find_arenas(&img);
        assert_eq!(arenas.len(), 1);
        assert_eq!(arenas[0].addr, arena);
        assert_eq!(arenas[0].top, top);
        assert_eq!(arenas[0].size, 0x1000);
        assert!(arenas[0].is_main, "an arena in libc file-backed data is main_arena");
    }

    #[test]
    fn reveal_safe_link_roundtrip() {
        // glibc mangles free-list pointers as (pos >> 12) ^ ptr.
        let pos = 0x7f00_0000_0120u64;
        let ptr = 0x7f00_0000_0450u64;
        assert_eq!(reveal_safe_link(pos, (pos >> 12) ^ ptr), ptr);
    }

    #[test]
    fn carve_finds_mmap_allocations() {
        // A standalone anon rw- region whose chunk header has IS_MMAPPED is a
        // large mmap-served allocation (glibc >= ~128 KiB), not a heap.
        const M: u64 = 0x7f00_1000_0000;
        let mut b = ImageBuilder::new();
        add_heap(&mut b, M, 0x101000);
        b.write_u64(M, 0);                        // prev_size
        b.write_u64(M + 8, 0x101000 | IS_MMAPPED); // size | IS_MMAPPED
        b.write(M + 0x10, &vec![0x42u8; 0x1000]);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 1);
        assert_eq!(inv.objects[0].addr, M + 0x10);
        assert_eq!(inv.objects[0].size, 0x100FF0);
        assert_eq!(inv.objects[0].state, ObjectState::Mmap);
    }

    #[test]
    fn carve_marks_tcache_freed_chunks() {
        // A heap with a tcache_perthread_struct (0x280 usable) whose entries[]
        // list a freed chunk as a PLAIN user pointer. The freed chunk's
        // successor keeps PREV_INUSE set (tcache does not clear it), so only
        // the tcache cross-reference can reveal it as freed.
        const L: u64 = 0x7faa_0000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, H_END - H);

        let arena = L + 0x100;
        let top = H + 0x2b0; // top chunk header after the two chunks below
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_NEXT_OFFSET, arena);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, H_END - H);

        // tcache struct: 0x280 usable (chunk 0x290) at H.
        place_chunk(&mut b, H, 0x280, PREV_INUSE, 0);
        // counts[0] = 1 (one freed 0x20-size chunk in bin 0).
        b.write_u64(H + 0x10, 1);
        // entries[0] (at user+0x80) = plain user pointer of the freed chunk.
        let freed_user = H + 0x2a0; // header H+0x290, user H+0x2a0
        b.write_u64(H + 0x10 + 0x80, freed_user);

        // Freed chunk: header H+0x290 (right after tcache), chunk 0x20, next
        // chunk's PREV_INUSE SET (tcache behavior) so the header heuristic
        // alone says "allocated".
        place_chunk(&mut b, H + 0x290, 0x10, PREV_INUSE, 0xCC);
        // Top chunk after it.
        place_top(&mut b, H + 0x2b0, H_END);

        let img = b.build();
        let inv = crate::carve(&img);
        assert_eq!(inv.objects.len(), 2, "tcache struct + freed chunk");
        let freed = inv
            .objects
            .iter()
            .find(|o| o.addr == freed_user)
            .expect("freed chunk carved");
        assert_eq!(freed.state, ObjectState::Freed, "tcache cross-ref must mark freed");
    }

    #[test]
    fn carve_marks_fastbin_freed_chunks() {
        // A chunk freed into a fastbin keeps the successor's PREV_INUSE set,
        // so only the arena fastbinsY cross-reference reveals it as freed.
        // Fastbin chains use PLAIN pointers (safe-linking is tcache-only).
        const L: u64 = 0x7faa_0000_0000;
        let mut b = ImageBuilder::new();
        add_libc(&mut b, L, 0x1000);
        add_heap(&mut b, H, H_END - H);

        let arena = L + 0x100;
        let top = H + 0x2d0; // after tcache + 2 chunks
        b.write_u64(arena + ARENA_TOP_OFFSET, top);
        b.write_u64(arena + ARENA_NEXT_OFFSET, arena);
        b.write_u64(arena + ARENA_SYSTEM_MEM_OFFSET, H_END - H);
        // fastbinsY[0] (0x20 size class) -> freed chunk HEADER H+0x290; that
        // chunk's mangled fd (at its user H+0x2a0) -> header H+0x2b0; fd=0 tail.
        let fc1_header = H + 0x290;
        let fc1_user = fc1_header + 0x10;
        let fc2_header = H + 0x2b0;
        let fc2_user = fc2_header + 0x10;
        b.write_u64(arena + 0x10, fc1_header); // fastbinsY[0] stores a header
        // tcache struct (counts all zero -> not a tcache candidate here).
        place_chunk(&mut b, H, 0x280, PREV_INUSE, 0);
        // Two freed chunks (headers with PREV_INUSE set so the header
        // heuristic alone would say "allocated").
        place_chunk(&mut b, fc1_header, 0x10, PREV_INUSE, 0xCC);
        place_chunk(&mut b, fc2_header, 0x10, PREV_INUSE, 0xCC);
        // Fastbin fd chain: safe-link mangled, stored at each chunk's user.
        b.write_u64(fc1_user, reveal_safe_link(fc1_user, fc2_header));
        b.write_u64(fc2_user, 0);
        place_top(&mut b, H + 0x2d0, H_END);

        let img = b.build();
        let inv = crate::carve(&img);
        let f1 = inv.objects.iter().find(|o| o.addr == fc1_user).expect("fc1");
        let f2 = inv.objects.iter().find(|o| o.addr == fc2_user).expect("fc2");
        assert_eq!(f1.state, ObjectState::Freed, "fastbin head must be freed");
        assert_eq!(f2.state, ObjectState::Freed, "fastbin fd-chain link must be freed");
        assert_eq!(f1.freed_reason, Some(crate::FreedReason::Fastbin));
    }

    #[test]
    fn arena_offset_contract() {
        // These offsets must match the glibc `malloc_state` layout used by the
        // fixture builder in naksheap-testkit. The two crates cannot depend on
        // each other, so this documents the contract.
        assert_eq!(ARENA_TOP_OFFSET, 0x60);
        assert_eq!(ARENA_NEXT_OFFSET, 0x870);
        assert_eq!(ARENA_SYSTEM_MEM_OFFSET, 0x888);
    }
}
