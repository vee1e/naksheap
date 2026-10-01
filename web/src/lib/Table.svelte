<script lang="ts">
  import type { Node } from './types'

  interface Props {
    nodes: Node[]
    selected: number | null
    onselect: (addr: number) => void
  }

  let { nodes, selected, onselect }: Props = $props()

  type Filter = 'all' | 'allocated' | 'freed' | 'root' | 'unreachable'
  let filter = $state<Filter>('all')
  let query = $state('')

  let visible = $derived.by(() => {
    const q = query.trim().toLowerCase()
    return nodes.filter((n) => {
      if (filter === 'allocated' && n.state !== 'allocated') return false
      if (filter === 'freed' && n.state !== 'freed') return false
      if (filter === 'root' && !n.is_root) return false
      if (filter === 'unreachable' && n.reachable_from_root) return false
      if (!q) return true
      return (
        '0x' + n.addr.toString(16).includes(q) ||
        n.ty.name.toLowerCase().includes(q) ||
        n.state.includes(q)
      )
    })
  })

  // A long dump can produce tens of thousands of rows; rendering them all
  // would lock the tab, so only the head is shown.
  const CAP = 300
  let shown = $derived(visible.slice(0, CAP))
  let overflow = $derived(Math.max(0, visible.length - CAP))

  function hex(n: number) {
    return '0x' + n.toString(16)
  }

  const FILTERS: [Filter, string][] = [
    ['all', 'all'],
    ['allocated', 'allocated'],
    ['freed', 'freed'],
    ['root', 'roots'],
    ['unreachable', 'unreachable'],
  ]
</script>

<section class="table">
  <div class="controls">
    <div class="tabs">
      {#each FILTERS as [key, text] (key)}
        <button class:on={filter === key} onclick={() => (filter = key)}>{text}</button>
      {/each}
    </div>
    <input
      type="search"
      placeholder="filter by address or type"
      bind:value={query}
      aria-label="filter objects"
    />
    <span class="count">{visible.length.toLocaleString()}</span>
  </div>

  <div class="scroll">
    <table>
      <thead>
        <tr>
          <th>address</th>
          <th>type</th>
          <th class="r">size</th>
          <th class="r">conf</th>
          <th>state</th>
        </tr>
      </thead>
      <tbody>
        {#each shown as n (n.addr)}
          <tr
            class:sel={selected === n.addr}
            onclick={() => onselect(n.addr)}
            tabindex="0"
            onkeydown={(e) => e.key === 'Enter' && onselect(n.addr)}
          >
            <td class="mono">{hex(n.addr)}</td>
            <td>
              {n.ty.name}
              {#if n.is_root}<span class="flag">root</span>{/if}
              {#if !n.reachable_from_root}<span class="flag">unref</span>{/if}
            </td>
            <td class="r mono">{n.size.toLocaleString()}</td>
            <td class="r mono">{(n.ty.confidence * 100).toFixed(0)}</td>
            <td class="state">{n.state}</td>
          </tr>
        {/each}
      </tbody>
    </table>
    {#if overflow > 0}
      <p class="more">
        {overflow.toLocaleString()} more not shown. narrow the filter, or use the graph to
        explore.
      </p>
    {/if}
  </div>
</section>

<style>
  .table {
    border: 1px solid var(--grey-2);
    display: flex;
    flex-direction: column;
    min-height: 0;
  }
  .controls {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 10px;
    border-bottom: 1px solid var(--grey-2);
    flex-wrap: wrap;
  }
  .tabs {
    display: flex;
    gap: 2px;
  }
  .tabs button {
    background: none;
    border: 1px solid transparent;
    color: var(--grey-4);
    padding: 2px 7px;
    cursor: pointer;
    font-size: 11px;
    border-radius: 2px;
  }
  .tabs button:hover {
    color: var(--ink);
  }
  .tabs button.on {
    color: var(--ink);
    border-color: var(--grey-3);
  }
  input {
    flex: 1 1 140px;
    min-width: 0;
    background: var(--paper);
    border: 1px solid var(--grey-2);
    color: var(--ink);
    font: inherit;
    font-size: 12px;
    padding: 3px 7px;
    border-radius: 2px;
  }
  input:focus {
    outline: none;
    border-color: var(--grey-4);
  }
  .count {
    font-size: 11px;
    color: var(--grey-4);
    font-variant-numeric: tabular-nums;
  }
  .scroll {
    overflow: auto;
    max-height: 340px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 12px;
  }
  th {
    position: sticky;
    top: 0;
    background: var(--paper);
    text-align: left;
    font-weight: 500;
    color: var(--grey-4);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    padding: 6px 10px;
    border-bottom: 1px solid var(--grey-2);
  }
  td {
    padding: 3px 10px;
    border-bottom: 1px solid var(--grey-1);
  }
  tr {
    cursor: pointer;
  }
  tr:hover td {
    background: var(--grey-1);
  }
  tr.sel td {
    background: var(--ink);
    color: var(--paper);
  }
  tr.sel .mono,
  tr.sel .state {
    color: var(--paper);
  }
  tr:focus-visible {
    outline: 1px solid var(--ink);
    outline-offset: -1px;
  }
  .r {
    text-align: right;
  }
  .mono {
    font-variant-numeric: tabular-nums;
  }
  .state {
    color: var(--grey-4);
  }
  .flag {
    border: 1px solid var(--grey-3);
    padding: 0 3px;
    margin-left: 5px;
    font-size: 9px;
    color: var(--grey-5);
  }
  /* The selected row inverts to an ink background, so the flag needs its
     border and text inverted too or it disappears into the row. */
  tr.sel .flag {
    border-color: var(--paper);
    color: var(--paper);
  }
  .more {
    margin: 0;
    padding: 8px 10px;
    font-size: 11px;
    color: var(--grey-4);
    border-top: 1px solid var(--grey-2);
  }
</style>
