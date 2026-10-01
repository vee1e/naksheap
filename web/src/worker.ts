/// <reference lib="webworker" />
//
// Runs the naksheap wasm module off the main thread. A dump of a few hundred
// MiB takes tens of seconds to carve and scan; doing that on the main thread
// would freeze the tab and kill the progress bar we are trying to show.
//
// Protocol: the page posts { bytes } and gets back a stream of
// { type: 'progress' | 'done' | 'error' } messages.

import init, { analyze_js, max_input_bytes } from '../pkg/naksheap_wasm.js'
import type { AnalyzeResult, WorkerIn, WorkerOut, Progress } from './lib/types'

let ready: Promise<void> | null = null

// The module is instantiated once and reused, so a second analysis does not
// pay the compile cost again.
function ensureModule(): Promise<void> {
  if (!ready) {
    ready = init().then(() => undefined)
  }
  return ready ?? Promise.resolve()
}

function post(msg: WorkerOut) {
  self.postMessage(msg)
}

self.onmessage = async (ev: MessageEvent<WorkerIn>) => {
  const { bytes } = ev.data
  try {
    await ensureModule()

    const cap = max_input_bytes()
    if (bytes.byteLength > cap) {
      post({
        type: 'error',
        message:
          `This dump is ${(bytes.byteLength / 1048576).toFixed(0)} MiB. ` +
          `The in-browser analyzer handles up to ${(cap / 1048576).toFixed(0)} MiB, ` +
          `because a browser tab cannot hold a larger heap graph in memory. ` +
          `Use the naksheap service for dumps this size.`,
      })
      return
    }

    // Progress arrives as a JSON string to keep the crossing cheap and the
    // wasm side free of JS object marshalling. The pipeline already throttles
    // these to roughly 200 updates, so stringifying here is not a bottleneck.
    const onProgress = (payload: string) => {
      try {
        post({ type: 'progress', progress: JSON.parse(payload) as Progress })
      } catch {
        // A malformed progress payload must not abort a running analysis.
      }
    }

    const json = analyze_js(new Uint8Array(bytes), onProgress)
    const result = JSON.parse(json) as AnalyzeResult
    post({ type: 'done', result })
  } catch (err) {
    // A wasm panic aborts the module and arrives here as an unhelpful Error, so
    // the message is normalised into something a user can act on.
    const message =
      err instanceof Error ? err.message : typeof err === 'string' ? err : 'analysis failed'
    post({ type: 'error', message })
  }
}
