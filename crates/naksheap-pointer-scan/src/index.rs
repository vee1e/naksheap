use naksheap_allocator_heuristics::Object;

/// Fast lookup from a virtual address to the carved object containing it.
///
/// Objects are sorted by `(addr, size)` once; [`ObjectIndex::target_at`] then
/// answers stabbing queries with a binary search for the rightmost object that
/// starts at or before the address, followed by a short backward walk.
///
/// # Lookup behavior
///
/// For the disjoint heaps naksheap normally targets, the walk exits after a
/// single check (O(log n) binary search + O(1)). Carve output can overlap
/// however — e.g. a corrupt-but-plausible chunk size yields an object whose
/// range swallows a real neighbor — so the walk keeps going backward while
/// *any* predecessor could still contain the address. That test uses a prefix
/// maximum of object ends, not only the immediate predecessor: a short
/// neighbour sitting just before the query must not hide a longer outer
/// object that started earlier and still covers the address. The walk still
/// returns the largest-start (innermost/smallest) container.
#[derive(Debug, Clone)]
pub struct ObjectIndex {
    objects: Vec<Object>,
    /// `max_end_upto[i]` is the maximum of `addr + size` for `objects[0..=i]`.
    max_end_upto: Vec<u64>,
}

/// Builds a fast lookup from a virtual address to the object containing it.
pub fn index_objects(objects: &[Object]) -> ObjectIndex {
    let mut sorted = objects.to_vec();
    sorted.sort_by_key(|o| (o.addr, o.size));
    let mut max_end_upto = Vec::with_capacity(sorted.len());
    let mut run = 0u64;
    for o in &sorted {
        run = run.max(o.addr.saturating_add(o.size));
        max_end_upto.push(run);
    }
    ObjectIndex {
        objects: sorted,
        max_end_upto,
    }
}

impl ObjectIndex {
    /// Returns the smallest object whose `[addr, addr + size)` contains
    /// `target`, or `None` if no carved object covers it.
    ///
    /// Runs in O(log n) for the binary search plus O(1) amortized for the
    /// backward walk on the disjoint heaps naksheap targets.
    pub fn target_at(&self, addr: u64) -> Option<&Object> {
        // Rightmost object that starts at or before `addr`, so it satisfies
        // `o.addr <= addr` (no underflow below).
        let mut i = self.objects.partition_point(|o| o.addr <= addr) as isize - 1;
        while i >= 0 {
            let o = &self.objects[i as usize];
            let delta = addr - o.addr;
            if delta < o.size {
                // `addr` lands inside this object's user area. Because starts
                // are scanned right-to-left, this is the object with the
                // largest start address containing `addr` — the
                // innermost/smallest container, exact even when carve output
                // overlaps.
                return Some(o);
            }
            // `o` ends at or before `addr`. Keep walking only while some
            // earlier object could still cover `addr`. The prefix maximum is
            // required: the immediate predecessor may be a short nested
            // object that ends before the query, while an outer object that
            // started earlier still contains it.
            if i == 0 {
                break;
            }
            if self.max_end_upto[i as usize - 1] <= addr {
                break;
            }
            i -= 1;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use naksheap_allocator_heuristics::ObjectState;

    fn obj(addr: u64, size: u64) -> Object {
        Object {
            addr,
            size,
            state: ObjectState::Allocated,
            arena: None,
            chunk_header: addr - 0x10,
            freed_reason: None,
        }
    }

    #[test]
    fn target_at_large_index_is_fast_and_exact() {
        const N: u64 = 100_000;
        let objects: Vec<Object> = (0..N)
            .map(|i| obj(0x1_0000_0000 + i * 0x100, 0x40))
            .collect();
        let index = index_objects(&objects);

        // Hit: the query address must resolve to exactly the object that owns
        // it. With 100k objects the old O(n) backward walk would be trivial to
        // catch on slow builds, so a passing run is the performance assertion.
        let mid = 0x1_0000_0000 + (N / 2) * 0x100;
        let t = index.target_at(mid + 0x20).expect("mid object");
        assert_eq!(t.addr, mid);

        let first = index.target_at(0x1_0000_0000).expect("first object");
        assert_eq!(first.addr, 0x1_0000_0000);

        let last = index.target_at(0x1_0000_0000 + (N - 1) * 0x100 + 0x3f);
        assert_eq!(last.map(|o| o.addr), Some(0x1_0000_0000 + (N - 1) * 0x100));
    }

    #[test]
    fn target_at_miss_at_end_terminates_immediately() {
        const N: u64 = 100_000;
        let objects: Vec<Object> = (0..N)
            .map(|i| obj(0x1_0000_0000 + i * 0x100, 0x40))
            .collect();
        let index = index_objects(&objects);

        // Address just past the final object's end: the early-exit must break
        // after one comparison instead of walking all 100k objects.
        let past_end = 0x1_0000_0000 + N * 0x100;
        assert!(index.target_at(past_end).is_none());
        assert!(index.target_at(past_end + 0x10_0000).is_none());
    }

    #[test]
    fn target_at_overlap_returns_innermost() {
        // Outer [0x610000, 0x610040) and inner [0x610010, 0x610030) overlap.
        // An interior address is contained by BOTH; the inner (larger-start)
        // object wins.
        let objects = vec![obj(0x610000, 0x40), obj(0x610010, 0x20)];
        let index = index_objects(&objects);
        assert_eq!(index.target_at(0x610018).unwrap().addr, 0x610010);
    }

    #[test]
    fn target_at_walk_continues_past_inner_to_outer() {
        // Outer O [0x2000, 0x2040), inner S [0x2010, 0x2020). A query inside O
        // but past S's end must still resolve to O: the walk continues past the
        // non-containing inner object because the predecessor still reaches
        // the address.
        let objects = vec![obj(0x2000, 0x40), obj(0x2010, 0x10)];
        let index = index_objects(&objects);
        assert_eq!(index.target_at(0x2030).unwrap().addr, 0x2000);
    }

    #[test]
    fn target_at_miss_with_earlier_large_object() {
        // Big B [0x2000, 0x2040), small S [0x2010, 0x2020) inside B. The query
        // sits past S's end and also past B's end: B would contain the address
        // if it extended that far, but it ends before, so the answer is None.
        let objects = vec![obj(0x2000, 0x40), obj(0x2010, 0x10)];
        let index = index_objects(&objects);
        assert!(index.target_at(0x2050).is_none());
    }

    #[test]
    fn target_at_outer_object_not_hidden_by_earlier_nested_neighbor() {
        // A = [0x1000, 0x1100), B = [0x1010, 0x1020), C = [0x1030, 0x1040).
        // Query 0x1050 sits past B and C but still inside A. Walking backward
        // from C used to stop at B (which ends before the query) and miss A.
        let objects = vec![obj(0x1000, 0x100), obj(0x1010, 0x10), obj(0x1030, 0x10)];
        let index = index_objects(&objects);
        assert_eq!(index.target_at(0x1050).unwrap().addr, 0x1000);
        // Innermost still wins when the query is inside a nested object.
        assert_eq!(index.target_at(0x1018).unwrap().addr, 0x1010);
        assert_eq!(index.target_at(0x1038).unwrap().addr, 0x1030);
    }
}
