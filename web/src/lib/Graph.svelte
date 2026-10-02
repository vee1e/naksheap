<script lang="ts">
  // Canvas force-directed graph. Deliberately the same algorithm as the
  // self-contained HTML report that the CLI writes, so a report file and the
  // web view of the same dump look alike.
  import { onMount } from 'svelte'
  import type { Node, GraphEdge } from './types'

  interface Props {
    nodes: Node[]
    edges: GraphEdge[]
    /** Address the user asked to focus, or null for "fit everything". */
    focus?: number | null
  }

  let { nodes, edges, focus = null }: Props = $props()

  let canvas: HTMLCanvasElement
  let selected = $state<number | null>(null)
  let hovered = $state<number | null>(null)

  interface Sim {
    pos: Float64Array
    vel: Float64Array
    idx: Map<number, number>
    links: [number, number][]
    bounds: { minX: number; maxX: number; minY: number; maxY: number }
  }

  let sim = $state<Sim | null>(null)
  let scale = $state(1)
  let panX = $state(0)
  let panY = $state(0)
  let settled = $state(false)

  const ITER = 300
  let iter = 0
  let raf = 0

  // Deterministic seeding: the same graph always lays out the same way, so two
  // runs can be compared by eye.
  function seededPositions(n: number): Float64Array {
    const pos = new Float64Array(n * 2)
    // Phyllotaxis seeding: even angular spacing on a golden-angle spiral gives
    // a good starting spread without randomness, so layouts are reproducible.
    const golden = Math.PI * (3 - Math.sqrt(5))
    for (let i = 0; i < n; i++) {
      const r = 10 + 180 * Math.sqrt((i + 0.5) / n)
      pos[i * 2] = Math.cos(i * golden) * r
      pos[i * 2 + 1] = Math.sin(i * golden) * r
    }
    return pos
  }

  function rebuild() {
    const n = nodes.length
    const pos = seededPositions(n)
    const idx = new Map<number, number>()
    for (let i = 0; i < n; i++) idx.set(nodes[i].addr, i)
    const links: [number, number][] = []
    for (const e of edges) {
      const s = idx.get(e.from)
      const t = idx.get(e.to)
      if (s !== undefined && t !== undefined) links.push([s, t])
    }
    sim = {
      pos,
      vel: new Float64Array(n * 2),
      idx,
      links,
      bounds: { minX: -200, maxX: 200, minY: -200, maxY: 200 },
    }
    iter = 0
    settled = false
  }

  function step(W: number, H: number) {
    if (!sim) return
    const n = nodes.length
    if (n === 0) {
      settled = true
      return
    }
    const k = Math.sqrt((W * H) / n)
    const dx = new Float64Array(n)
    const dy = new Float64Array(n)
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const ex = sim.pos[i * 2] - sim.pos[j * 2]
        const ey = sim.pos[i * 2 + 1] - sim.pos[j * 2 + 1]
        const d = Math.sqrt(ex * ex + ey * ey) || 0.01
        const f = Math.min((k * k) / d, 2000)
        const ux = (ex / d) * f
        const uy = (ey / d) * f
        dx[i] += ux
        dy[i] += uy
        dx[j] -= ux
        dy[j] -= uy
      }
    }
    for (let i = 0; i < sim.links.length; i++) {
      const [s, t] = sim.links[i]
      const ex = sim.pos[s * 2] - sim.pos[t * 2]
      const ey = sim.pos[s * 2 + 1] - sim.pos[t * 2 + 1]
      const d = Math.sqrt(ex * ex + ey * ey) || 0.01
      const f = (d * d) / k
      const ux = (ex / d) * f
      const uy = (ey / d) * f
      dx[s] -= ux
      dy[s] -= uy
      dx[t] += ux
      dy[t] += uy
    }
    let minX = Infinity
    let maxX = -Infinity
    let minY = Infinity
    let maxY = -Infinity
    for (let i = 0; i < n; i++) {
      dx[i] -= sim.pos[i * 2] * 0.02
      dy[i] -= sim.pos[i * 2 + 1] * 0.02
      const d = Math.sqrt(dx[i] * dx[i] + dy[i] * dy[i]) || 0.01
      const lim = d / (2 * Math.max(d, 0.05 * k))
      sim.vel[i * 2] = (sim.vel[i * 2] + (dx[i] / d) * lim) * 0.85
      sim.vel[i * 2 + 1] = (sim.vel[i * 2 + 1] + (dy[i] / d) * lim) * 0.85
      sim.pos[i * 2] += sim.vel[i * 2]
      sim.pos[i * 2 + 1] += sim.vel[i * 2 + 1]
      if (sim.pos[i * 2] < minX) minX = sim.pos[i * 2]
      if (sim.pos[i * 2] > maxX) maxX = sim.pos[i * 2]
      if (sim.pos[i * 2 + 1] < minY) minY = sim.pos[i * 2 + 1]
      if (sim.pos[i * 2 + 1] > maxY) maxY = sim.pos[i * 2 + 1]
    }
    sim.bounds = { minX, maxX, minY, maxY }
  }

  function sx(i: number) {
    return sim!.pos[i * 2] * scale + panX
  }
  function sy(i: number) {
    return sim!.pos[i * 2 + 1] * scale + panY
  }

  // Size is mapped onto radius so a large allocation is visibly larger. The
  // mapping is logarithmic because heaps span orders of magnitude: one real
  // core had objects from 16 B to 1 MiB, a ratio of ~65,000x. The result is
  // clamped because an unclamped log still gives that node a radius large
  // enough to dominate the layout bounds, and the fit-to-view then zooms out
  // until the rest of the graph is a cluster of dots off the side.
  function radius(node: Node) {
    return Math.min(28, 4 + (Math.log2(Math.max(node.size, 16)) - 4) * 1.4)
  }

  function nodeStyle(node: Node) {
    if (node.is_root) return { fill: 'var(--ink)', stroke: 'var(--ink)', dash: [] as number[], w: 2.5 }
    if (!node.reachable_from_root)
      return { fill: 'var(--paper)', stroke: 'var(--ink)', dash: [3, 2] as number[], w: 2 }
    if (node.state === 'freed')
      return { fill: 'var(--paper)', stroke: 'var(--grey-4)', dash: [2, 2] as number[], w: 1 }
    return { fill: 'var(--paper)', stroke: 'var(--ink)', dash: [] as number[], w: 2 }
  }

  function cssVar(name: string) {
    const v = getComputedStyle(canvas).getPropertyValue(name).trim()
    return v || '#000'
  }

  function fit() {
    if (!sim) return
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    const b = sim.bounds
    const bw = Math.max(b.maxX - b.minX, 1)
    const bh = Math.max(b.maxY - b.minY, 1)
    scale = Math.min(w / (bw + 140), h / (bh + 140)) * 0.9
    panX = w / 2 - ((b.minX + b.maxX) / 2) * scale
    panY = h / 2 - ((b.minY + b.maxY) / 2) * scale
  }

  function draw() {
    if (!sim) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const dpr = window.devicePixelRatio || 1
    const w = canvas.clientWidth
    const h = canvas.clientHeight
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, w, h)
    ctx.fillStyle = cssVar('--paper')
    ctx.fillRect(0, 0, w, h)

    const dim = cssVar('--grey-2')
    const faint = cssVar('--grey-4')

    ctx.save()
    for (let i = 0; i < sim.links.length; i++) {
      const [s, t] = sim.links[i]
      const e = edges[i]
      const confirmed = e?.confirmed
      ctx.strokeStyle = confirmed ? cssVar('--ink') : dim
      ctx.lineWidth = confirmed ? 1.5 : 1
      ctx.setLineDash(confirmed ? [] : [3, 3])
      ctx.beginPath()
      ctx.moveTo(sx(s), sy(s))
      ctx.lineTo(sx(t), sy(t))
      ctx.stroke()
    }
    ctx.setLineDash([])

    ctx.font =
      '10px ' + (getComputedStyle(canvas).getPropertyValue('--mono').trim() || 'monospace')
    ctx.textAlign = 'center'
    for (let i = 0; i < nodes.length; i++) {
      const node = nodes[i]
      const st = nodeStyle(node)
      const x = sx(i)
      const y = sy(i)
      const r = radius(node)
      ctx.beginPath()
      ctx.arc(x, y, r, 0, Math.PI * 2)
      ctx.fillStyle = st.fill
      ctx.fill()
      ctx.strokeStyle = st.stroke
      ctx.lineWidth = st.w
      ctx.setLineDash(st.dash)
      ctx.stroke()
      ctx.setLineDash([])
      if (i === selected || i === hovered) {
        ctx.beginPath()
        ctx.arc(x, y, r + 4, 0, Math.PI * 2)
        ctx.strokeStyle = cssVar('--ink')
        ctx.setLineDash([2, 2])
        ctx.lineWidth = 1
        ctx.stroke()
        ctx.setLineDash([])
      }
      // Labels are dropped when zoomed far out, otherwise a large graph turns
      // into a wall of overlapping hex. The threshold is low because
      // fit-to-view on a real dump routinely lands below 0.5.
      if (scale > 0.18) {
        ctx.fillStyle = i === selected ? cssVar('--ink') : faint
        ctx.fillText('0x' + node.addr.toString(16), x, y + r + 11)
      }
    }
    ctx.restore()
  }

  function pick(px: number, py: number) {
    if (!sim) return null
    let best: number | null = null
    let bestD = Infinity
    for (let i = 0; i < nodes.length; i++) {
      const r = radius(nodes[i]) + 5
      const d = (px - sx(i)) ** 2 + (py - sy(i)) ** 2
      if (d < r * r && d < bestD) {
        bestD = d
        best = i
      }
    }
    return best
  }

  let dragging = false
  let moved = false
  let lastX = 0
  let lastY = 0

  function onDown(e: PointerEvent) {
    dragging = true
    moved = false
    lastX = e.clientX
    lastY = e.clientY
    ;(e.target as HTMLElement).setPointerCapture(e.pointerId)
  }

  function onMove(e: PointerEvent) {
    if (dragging) {
      panX += e.clientX - lastX
      panY += e.clientY - lastY
      lastX = e.clientX
      lastY = e.clientY
      if (Math.abs(e.clientX - lastX) + Math.abs(e.clientY - lastY) > 1) moved = true
      draw()
    } else {
      const rect = canvas.getBoundingClientRect()
      const h = pick(e.clientX - rect.left, e.clientY - rect.top)
      if (h !== hovered) {
        hovered = h
        canvas.style.cursor = h !== null ? 'pointer' : 'grab'
        draw()
      }
    }
  }

  function onUp(e: PointerEvent) {
    if (dragging && !moved) {
      const rect = canvas.getBoundingClientRect()
      const hit = pick(e.clientX - rect.left, e.clientY - rect.top)
      selected = hit
    }
    dragging = false
  }

  function onWheel(e: WheelEvent) {
    e.preventDefault()
    const rect = canvas.getBoundingClientRect()
    const mx = e.clientX - rect.left
    const my = e.clientY - rect.top
    const f = e.deltaY < 0 ? 1.12 : 1 / 1.12
    const ns = Math.max(0.05, Math.min(40, scale * f))
    panX = mx - (mx - panX) * (ns / scale)
    panY = my - (my - panY) * (ns / scale)
    scale = ns
    draw()
  }

  export function fitToView() {
    fit()
    draw()
  }

  export function replay() {
    rebuild()
    start()
  }

  function start() {
    cancelAnimationFrame(raf)
    const w = canvas?.clientWidth || 800
    const h = canvas?.clientHeight || 600
    const slice = Math.max(1, Math.floor(ITER / 30))
    const tick = () => {
      for (let s = 0; s < slice && iter < ITER; s++, iter++) step(w, h)
      draw()
      if (iter < ITER) {
        raf = requestAnimationFrame(tick)
      } else {
        // Fit only once the layout has settled. Fitting early fits to a
        // collapsed graph and then the real layout expands past the viewport,
        // which is how nodes end up off screen.
        fit()
        draw()
        settled = true
      }
    }
    raf = requestAnimationFrame(tick)
  }

  onMount(() => {
    const onResize = () => {
      const dpr = window.devicePixelRatio || 1
      canvas.width = canvas.clientWidth * dpr
      canvas.height = canvas.clientHeight * dpr
      draw()
    }
    onResize()
    rebuild()
    start()
    window.addEventListener('resize', onResize)
    return () => {
      window.removeEventListener('resize', onResize)
      cancelAnimationFrame(raf)
    }
  })

  // Focus a specific address: select it and centre it.
  $effect(() => {
    if (focus === null || focus === undefined || !sim) return
    const i = sim.idx.get(focus)
    if (i === undefined) return
    selected = i
    const w = canvas?.clientWidth || 800
    const h = canvas?.clientHeight || 600
    panX = w / 2 - sim.pos[i * 2] * scale
    panY = h / 2 - sim.pos[i * 2 + 1] * scale
    draw()
  })

  let onSelect = $state<(node: Node | null) => void>(() => {})
  export function bindSelect(fn: (node: Node | null) => void) {
    onSelect = fn
  }

  // Push the selection upward after the pointer handler sets it.
  $effect(() => {
    onSelect(selected !== null ? nodes[selected] : null)
  })

  let ready = $derived(!!sim)
</script>

<div class="wrap">
  <canvas
    bind:this={canvas}
    onpointerdown={onDown}
    onpointermove={onMove}
    onpointerup={onUp}
    onwheel={onWheel}
    class:settled
  ></canvas>
  {#if !ready}
    <p class="empty">no graph</p>
  {/if}
</div>

<style>
  .wrap {
    position: relative;
    width: 100%;
    height: 100%;
    min-height: 320px;
  }
  canvas {
    display: block;
    width: 100%;
    height: 100%;
    touch-action: none;
    cursor: grab;
  }
  .empty {
    position: absolute;
    inset: 0;
    display: grid;
    place-items: center;
    color: var(--grey-4);
    margin: 0;
  }
</style>
