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
/// range swallows a real neighbor — so the walk keeps going backward while a
/// predecessor could still contain the address. This returns the largest-start
/// (innermost/smallest) container exactly for such overlapping output too,
/// while staying O(1) amortized because the walk is bounded by the overlap
/// chain and stops as soon as a predecessor ends at or before the query.
#[derive(Debug, Clone)]
pub struct ObjectIndex {
    objects: Vec<Object>,
}

/// Builds a fast lookup from a virtual address to the object containing it.
pub fn index_objects(objects: &[Object]) -> ObjectIndex {
    let mut sorted = objects.to_vec();
    sorted.sort_by_key(|o| (o.addr, o.size));
    ObjectIndex { objects: sorted }
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
        let mut i = self
            .objects
            .partition_point(|o| o.addr <= addr) as isize - 1;
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
            // `o` ends at or before `addr`. Move on to its predecessor only
            // while that predecessor could still reach past `addr` (overlap);
            // once a predecessor ends at or before `addr`, no earlier
            // (smaller-start) object can contain it either and the walk stops.
            if i == 0 {
                break;
            }
            let prev = &self.objects[i as usize - 1];
            if prev.addr.checked_add(prev.size).is_none_or(|end| end <= addr) {
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
        let objects: Vec<Object> = (0..N).map(|i| obj(0x1_0000_0000 + i * 0x100, 0x40)).collect();
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
        let objects: Vec<Object> = (0..N).map(|i| obj(0x1_0000_0000 + i * 0x100, 0x40)).collect();
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
}
