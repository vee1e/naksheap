// The demo dump is the repository's own checked-in synthetic fixture
// (fixtures/toy-server.core, ~58 KiB) with its ground-truth manifest. It is
// served as a static asset rather than generated in-page, so the production
// wasm does not have to link naksheap-testkit just to power a demo button.
//
// It is a synthetic core with a known object layout, so the demo shows the
// tool doing real work rather than a canned screenshot.

const SAMPLE_URL = '/sample.core'

let cached: ArrayBuffer | null = null

export async function makeSampleFixture(): Promise<ArrayBuffer> {
  if (cached) return cached
  const res = await fetch(SAMPLE_URL)
  if (!res.ok) {
    throw new Error(`could not load the sample dump (${res.status})`)
  }
  cached = await res.arrayBuffer()
  return cached
}
