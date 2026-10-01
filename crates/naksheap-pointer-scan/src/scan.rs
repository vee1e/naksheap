use std::collections::{HashMap, HashSet};

use naksheap_allocator_heuristics::{HeapInventory, Object, ObjectState};
use naksheap_core_parse::{AddressSpace, ThreadContext};
use rayon::prelude::*;

use crate::index::{index_objects, ObjectIndex};
use crate::roots::scan_thread;
use crate::{Edge, EdgeSource, Root, ScanOptions, ScanResult};

/// Reports scan progress as `(objects_done, objects_total)`.
pub type Progress<'a> = &'a (dyn Fn(usize, usize) + Sync);

/// Full scan: object->object edges, plus stack/register roots and edges.
pub fn scan(
    image: &(dyn AddressSpace + Sync),
    inventory: &HeapInventory,
    threads: &[ThreadContext],
    options: &ScanOptions,
) -> ScanResult {
    scan_with_progress(image, inventory, threads, options, &|_, _| {})
}

/// [`scan`], reporting object-scan progress via `progress`.
///
/// The callback is invoked as each object's scan completes, so a caller can
/// drive a progress bar. It must be cheap and must not block: it runs inside
/// rayon's worker pool.
pub fn scan_with_progress(
    image: &(dyn AddressSpace + Sync),
    inventory: &HeapInventory,
    threads: &[ThreadContext],
    options: &ScanOptions,
    progress: Progress<'_>,
) -> ScanResult {
    let index = index_objects(&inventory.objects);
    let alignment = options.alignment.max(1);

    // A freed object's user bytes are allocator free-list garbage (fd/bk
    // words), so an edge that ORIGINATES in a freed object must never count
    // toward confirmation. Build the freed-address set once here.
    let freed_sources: HashSet<u64> = inventory
        .objects
        .iter()
        .filter(|o| o.state == ObjectState::Freed)
        .map(|o| o.addr)
        .collect();

    let mut edges: Vec<Edge> = Vec::new();
    let mut strays: Vec<u64> = Vec::new();
    // Object count is the progress denominator for the object scan; thread
    // scans extend the same counter past it.
    let total = inventory.objects.len();

    if options.scan_objects {
        // Each object collects its own strays into a Vec capped at
        // `per_object_cap`, so a single noisy object cannot flood memory. The
        // results are merged and filtered deterministically below.
        let per_object_cap = options.max_strays.max(1);
        // `enumerate` gives a per-object completion index, so the callback
        // advances the caller's progress bar during the scan instead of only
        // reporting at the end. The callback runs on rayon worker threads, so
        // it must be cheap and non-blocking.
        let chunks: Vec<(Vec<Edge>, Vec<u64>)> = inventory
            .objects
            .par_iter()
            .map(|o| scan_object(image, &index, o, options, alignment, per_object_cap))
            .enumerate()
            .map(|(i, v)| {
                progress(i + 1, total);
                v
            })
            .collect();
        for (mut e, mut s) in chunks {
            edges.append(&mut e);
            strays.append(&mut s);
        }
        // Deterministic post-merge filtering: which strays survive must never
        // depend on parallel scheduling order, so sort, dedup, then truncate.
        strays.sort_unstable();
        strays.dedup();
        strays.truncate(options.max_strays);
    }

    let mut roots: Vec<Root> = Vec::new();
    if options.scan_registers || options.scan_stacks {
        for (i, thread) in threads.iter().enumerate() {
            let (mut r, mut e) = scan_thread(image, thread, &index, options);
            roots.append(&mut r);
            edges.append(&mut e);
            // Thread stacks are usually few and each is a long single scan, so
            // report per thread rather than per word.
            progress(total + i + 1, total + threads.len());
        }
    }

    if !options.include_freed_targets {
        edges.retain(|e| !target_is_freed(&index, e.to));
        roots.retain(|r| !target_is_freed(&index, r.value));
    }

    // Source object sizes, used to exclude spill-area offsets (words at or
    // past the reported usable size, in the next chunk's `prev_size`) from
    // confirmation: they are dead-memory reads, not deliberate references.
    let source_sizes: HashMap<u64, u64> =
        inventory.objects.iter().map(|o| (o.addr, o.size)).collect();
    dedup_and_confirm(&mut edges, &freed_sources, &source_sizes);

    ScanResult {
        edges,
        roots,
        stray_pointers: strays,
    }
}

/// Scans one object's user area at `alignment`-byte strides and records every
/// word that resolves to another carved object as an [`Edge`]. Words that point
/// outside every object are collected as strays, deterministically capped at
/// `stray_cap` for this object; the caller merges all per-object lists and
/// applies the global `max_strays` truncation.
fn scan_object(
    image: &(dyn AddressSpace + Sync),
    index: &ObjectIndex,
    o: &Object,
    options: &ScanOptions,
    alignment: u64,
    stray_cap: usize,
) -> (Vec<Edge>, Vec<u64>) {
    let mut edges = Vec::new();
    let mut strays = Vec::new();
    let word = image.pointer_width() as u64;
    // In-use glibc chunks may extend their data 8 bytes past the reported
    // usable size into the next chunk's `prev_size` field (glibc uses that
    // space for small allocations, e.g. a 24-byte std::vector's third word
    // lands at offset 0x10 of a 0x20 chunk). Scan that spill area so the
    // final pointer word of minimal-size objects is not missed. Freed and
    // mmapped chunks carry free-list/standalone data instead, so they get no
    // spill.
    let scan_extent = if o.state == ObjectState::Allocated {
        o.size.saturating_add(8)
    } else {
        o.size
    };
    let mut off = 0u64;
    while let Some(end) = off.checked_add(word) {
        if end > scan_extent {
            break;
        }
        let addr = match o.addr.checked_add(off) {
            Some(a) => a,
            None => break,
        };
        if let Some(w) = image.read_word(addr) {
            if w != 0 {
                if w >= o.chunk_header && w <= o.addr {
                    // Pointer into this object's own chunk header / header
                    // area, or the degenerate self-loop exactly at `o.addr`:
                    // not a reference edge.
                } else if let Some(t) = index.target_at(w) {
                    if options.include_freed_targets || t.state != ObjectState::Freed {
                        edges.push(Edge {
                            from: o.addr,
                            to: t.addr,
                            offset: off,
                            confirmed: false,
                            source: EdgeSource::Object,
                        });
                    }
                } else if strays.len() < stray_cap {
                    strays.push(w);
                }
            }
        }
        off += alignment;
    }
    (edges, strays)
}

/// True when `value` resolves into a freed carved object.
fn target_is_freed(index: &ObjectIndex, value: u64) -> bool {
    index
        .target_at(value)
        .is_some_and(|o| o.state == ObjectState::Freed)
}

/// Deduplicates edges by `(from, to, offset)` keeping the first, then computes
/// the `confirmed` flag. An edge is confirmed when its target is referenced by
/// two or more distinct *object* sources, or when it is an object edge whose
/// target holds a back-pointer into the source object. Stack and register
/// (root) edges never count as confirming sources: a single stale stack word or
/// register value must not elevate an object edge to confirmed. Edges that
/// originate in freed objects are free-list garbage (stale fd/bk words) and
/// likewise never count toward the `>= 2` rule or the back-pointer rule.
/// Spill-area edges (offset at or past the source's reported usable size, i.e.
/// words read from the next chunk's dead `prev_size`) are also excluded from
/// confirmation: they are incidental dead-memory reads, not deliberate links.
fn dedup_and_confirm(
    edges: &mut Vec<Edge>,
    freed_sources: &HashSet<u64>,
    source_sizes: &HashMap<u64, u64>,
) {
    let mut seen: HashSet<(u64, u64, u64)> = HashSet::new();
    edges.retain(|e| seen.insert((e.from, e.to, e.offset)));

    // Bounded source bookkeeping: the rule only needs `>= 2` distinct sources,
    // so per target we store just the first two DISTINCT (from) values in a
    // flat pair instead of a per-target HashSet. `0` is the empty-slot
    // sentinel; object addresses are never 0. Once the second distinct source
    // is recorded, further sources cannot change the outcome and are ignored.
    let mut sources: HashMap<u64, (u64, u64)> = HashMap::new();
    // Reverse-pair lookup for the back-pointer rule, derived once from the
    // (already deduplicated) object edge list rather than a parallel set.
    let mut object_pairs: HashSet<(u64, u64)> = HashSet::new();
    for e in edges.iter() {
        // Only object edges count toward confirmation; freed-object edges are
        // stale free-list words and are excluded from both structures.
        let spill = source_sizes
            .get(&e.from)
            .is_some_and(|size| e.offset >= *size);
        if e.source != EdgeSource::Object
            || freed_sources.contains(&e.from)
            || spill
        {
            continue;
        }
        object_pairs.insert((e.from, e.to));
        let pair = sources.entry(e.to).or_insert((e.from, 0));
        if pair.0 != e.from && pair.1 == 0 {
            pair.1 = e.from;
        }
    }
    for e in edges.iter_mut() {
        let distinct = match sources.get(&e.to) {
            Some((_, 0)) => 1,
            Some(_) => 2,
            None => 0,
        };
        let backref =
            e.source == EdgeSource::Object && object_pairs.contains(&(e.to, e.from));
        e.confirmed = distinct >= 2 || backref;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edge(from: u64, to: u64) -> Edge {
        Edge {
            from,
            to,
            offset: 0x10,
            confirmed: false,
            source: EdgeSource::Object,
        }
    }

    #[test]
    fn freed_object_edge_does_not_confirm_target() {
        // A (live) and F (freed) both point at live target T. F's stale
        // free-list word must not count toward the `>= 2` rule, so the A->T
        // edge stays unconfirmed.
        let mut edges = vec![edge(0x1000, 0x3000), edge(0x2000, 0x3000)];
        let freed = HashSet::from([0x2000u64]);
        dedup_and_confirm(&mut edges, &freed, &HashMap::new());
        let a_t = edges
            .iter()
            .find(|e| e.from == 0x1000 && e.to == 0x3000)
            .expect("A->T edge");
        assert!(!a_t.confirmed, "freed object's stale word must not confirm");
    }

    #[test]
    fn two_live_sources_still_confirm() {
        let mut edges = vec![edge(0x1000, 0x3000), edge(0x2000, 0x3000)];
        let freed = HashSet::new();
        dedup_and_confirm(&mut edges, &freed, &HashMap::new());
        for e in edges.iter().filter(|e| e.to == 0x3000) {
            assert!(e.confirmed, "two live sources confirm the target");
        }
    }

    #[test]
    fn freed_source_cannot_trigger_back_pointer() {
        // A -> F with F freed, and a stale F -> A free-list word. Excluding
        // the freed F->A edge from `object_pairs` means A->F cannot be
        // confirmed by F's back-pointer.
        let mut edges = vec![edge(0x1000, 0x2000), edge(0x2000, 0x1000)];
        let freed = HashSet::from([0x2000u64]);
        dedup_and_confirm(&mut edges, &freed, &HashMap::new());
        let a_f = edges
            .iter()
            .find(|e| e.from == 0x1000 && e.to == 0x2000)
            .expect("A->F edge");
        assert!(!a_f.confirmed, "freed object's back-pointer must not confirm");
    }
}
