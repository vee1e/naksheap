<script lang="ts">
  import Dropzone from './lib/Dropzone.svelte'
  import ProgressBar from './lib/ProgressBar.svelte'
  import Graph from './lib/Graph.svelte'
  import Table from './lib/Table.svelte'
  import Detail from './lib/Detail.svelte'
  import type { AnalyzeResult, Node, Progress, WorkerOut } from './lib/types'

  let result = $state<AnalyzeResult | null>(null)
  let progress = $state<Progress | null>(null)
  let busy = $state(false)
  let error = $state<string | null>(null)
  let selectedAddr = $state<number | null>(null)
  let elapsedMs = $state(0)

  let worker: Worker | null = null
  let startedAt = 0
  let ticker: ReturnType<typeof setInterval> | null = null

  let graphRef = $state<Graph | null>(null)

  // The sample dump is generated in-page by the analyzer's own testkit rather
  // than fetched, so the demo works offline and stays honest about what the
  // tool does.
  async function loadSample() {
    if (busy) return
    busy = true
    error = null
    try {
      const { makeSampleFixture } = await import('./lib/sample')
      const bytes = await makeSampleFixture()
      run(new Uint8Array(bytes).buffer)
    } catch (e) {
      error = e instanceof Error ? e.message : 'could not build the sample dump'
      busy = false
    }
  }

  function run(buffer: ArrayBuffer) {
    error = null
    result = null
    progress = null
    selectedAddr = null
    busy = true
    startedAt = performance.now()
    elapsedMs = 0
    ticker = setInterval(() => {
      elapsedMs = performance.now() - startedAt
    }, 100)

    worker?.terminate()
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })

    worker.onmessage = (ev: MessageEvent<WorkerOut>) => {
      const msg = ev.data
      if (msg.type === 'progress') {
        progress = msg.progress
      } else if (msg.type === 'done') {
        result = msg.result
        finish()
      } else {
        error = msg.message
        finish()
      }
    }
    worker.onerror = (ev) => {
      error = ev.message || 'the analysis worker crashed'
      finish()
    }
    worker.postMessage({ bytes: buffer }, [buffer])
  }

  function finish() {
    busy = false
    elapsedMs = performance.now() - startedAt
    if (ticker) clearInterval(ticker)
    ticker = null
  }

  function onFile(file: File) {
    if (busy) return
    // Read the file into memory here; the worker gets ownership of the buffer.
    file
      .arrayBuffer()
      .then((buf) => run(buf))
      .catch((e) => {
        error = e instanceof Error ? e.message : 'could not read the file'
        busy = false
      })
  }

  function select(addr: number) {
    selectedAddr = addr
  }

  let selectedNode = $derived<Node | null>(
    result && selectedAddr !== null
      ? (result.graph.nodes.find((n) => n.addr === selectedAddr) ?? null)
      : null,
  )

  let stats = $derived(result?.graph.stats ?? null)
</script>

<main>
  <header>
    <h1>naksheap</h1>
    <p class="tagline">reconstruct the heap from a core dump</p>
    <p class="privacy">
      runs in this tab. the dump is never uploaded, never written to disk, and nothing is sent
      anywhere.
    </p>
  </header>

  {#if !result && !busy}
    <Dropzone busy={busy} onfile={onFile} onsample={loadSample} meta={null} />
  {/if}

  {#if error}
    <div class="error" role="alert">
      <p>{error}</p>
      <button onclick={() => (error = null)}>dismiss</button>
    </div>
  {/if}

  {#if busy}
    <ProgressBar {progress} {elapsedMs} />
  {/if}

  {#if result && stats}
    <section class="stats">
      <div><b>{stats.total_objects.toLocaleString()}</b><span>objects</span></div>
      <div><b>{stats.allocated.toLocaleString()}</b><span>allocated</span></div>
      <div><b>{stats.freed.toLocaleString()}</b><span>freed</span></div>
      <div><b>{stats.root_reachable.toLocaleString()}</b><span>reachable</span></div>
      <div><b>{stats.edges.toLocaleString()}</b><span>edges</span></div>
      <div><b>{stats.confirmed_edges.toLocaleString()}</b><span>confirmed</span></div>
      <div><b>{stats.clusters.toLocaleString()}</b><span>layouts</span></div>
      <div><b>{stats.max_depth}</b><span>depth</span></div>
    </section>

    {#if result.meta.truncated}
      <p class="warn">
        this dump looks truncated: its memory ranges extend past the end of the file, so the
        results are partial.
      </p>
    {/if}

    <section class="graphpane">
      <Graph
        bind:this={graphRef}
        nodes={result.graph.nodes}
        edges={result.graph.edges}
        focus={selectedAddr}
      />
      <Detail node={selectedNode} />
    </section>

    <div class="graphctl">
      <button onclick={() => graphRef?.fitToView()}>fit</button>
      <button onclick={() => graphRef?.replay()}>replay layout</button>
      <span class="hint">drag to pan, scroll to zoom, click a node</span>
    </div>

    <Table nodes={result.graph.nodes} selected={selectedAddr} onselect={select} />

    <footer>
      <p>
        {result.meta.process ?? 'unknown process'} · {result.meta.format} ·
        {result.meta.threads}
        {result.meta.threads === 1 ? 'thread' : 'threads'} ·
        {(result.meta.input_bytes / 1048576).toFixed(1)} MiB · analyzed in {(elapsedMs / 1000).toFixed(1)}s
      </p>
      {#if result.meta.exec_path}
        <p class="dim">{result.meta.exec_path}</p>
      {/if}
    </footer>
  {/if}
</main>

<style>
  main {
    max-width: 1180px;
    margin: 0 auto;
    padding: 40px 20px 64px;
  }
  header {
    margin-bottom: 26px;
  }
  h1 {
    font-size: 22px;
    font-weight: 600;
    margin: 0;
    letter-spacing: -0.02em;
  }
  .tagline {
    margin: 2px 0 0;
    color: var(--grey-5);
    font-size: 13px;
  }
  .privacy {
    margin: 12px 0 0;
    font-size: 11px;
    color: var(--grey-4);
    max-width: 58ch;
    line-height: 1.6;
  }

  .error {
    border: 1px solid var(--ink);
    padding: 12px 14px;
    margin: 16px 0;
    font-size: 12px;
  }
  .error p {
    margin: 0 0 10px;
  }
  .error button {
    border-color: var(--grey-3);
    color: var(--grey-5);
  }
  .error button:hover {
    border-color: var(--ink);
    background: var(--ink);
    color: var(--paper);
  }

  .stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(96px, 1fr));
    gap: 1px;
    background: var(--grey-2);
    border: 1px solid var(--grey-2);
    margin: 18px 0;
  }
  .stats div {
    background: var(--paper);
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .stats b {
    font-weight: 600;
    font-size: 17px;
    font-variant-numeric: tabular-nums;
  }
  .stats span {
    font-size: 10px;
    color: var(--grey-4);
    text-transform: uppercase;
    letter-spacing: 0.06em;
  }

  .warn {
    border: 1px solid var(--ink);
    padding: 8px 12px;
    font-size: 12px;
    margin: 0 0 16px;
  }

  .graphpane {
    display: grid;
    grid-template-columns: 1fr 300px;
    gap: 1px;
    background: var(--grey-2);
    border: 1px solid var(--grey-2);
    height: 460px;
  }
  @media (max-width: 860px) {
    .graphpane {
      grid-template-columns: 1fr;
      height: auto;
    }
    .graphpane :global(.wrap) {
      height: 340px;
    }
  }

  .graphctl {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin: 8px 0 20px;
    font-size: 11px;
    color: var(--grey-4);
  }
  .graphctl .hint {
    margin-left: auto;
  }
  .dim {
    color: var(--grey-4);
  }

  footer {
    margin-top: 26px;
    padding-top: 14px;
    border-top: 1px solid var(--grey-2);
    font-size: 11px;
    color: var(--grey-4);
  }
  footer p {
    margin: 0 0 2px;
  }
</style>
