<script lang="ts">
  import type { Progress } from './types'

  interface Props {
    progress: Progress | null
    elapsedMs: number
  }

  let { progress, elapsedMs }: Props = $props()

  const LABELS: Record<string, string> = {
    parse: 'reading core headers',
    carve: 'carving heap objects',
    scan: 'scanning for pointers',
    infer: 'inferring types',
    serialize: 'serializing result',
  }

  let pct = $derived(Math.round((progress?.fraction ?? 0) * 100))
  let secs = $derived((elapsedMs / 1000).toFixed(1))
</script>

<div class="bar" role="status" aria-live="polite">
  <div class="row">
    <span class="stage">{progress ? (LABELS[progress.stage] ?? progress.stage) : 'starting'}</span>
    <span class="num">
      {pct}% <span class="dim">· {secs}s</span>
    </span>
  </div>
  <div class="track">
    <div class="fill" style:width="{pct}%"></div>
  </div>
  {#if progress}
    <p class="detail">
      {progress.done.toLocaleString()} / {progress.total.toLocaleString()} in stage
    </p>
  {/if}
</div>

<style>
  .bar {
    margin: 14px 0 4px;
  }
  .row {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    font-size: 12px;
    margin-bottom: 6px;
  }
  .stage {
    color: var(--ink);
  }
  .num {
    color: var(--grey-5);
    font-variant-numeric: tabular-nums;
  }
  .dim {
    color: var(--grey-3);
  }
  .track {
    height: 2px;
    background: var(--grey-2);
    overflow: hidden;
  }
  .fill {
    height: 100%;
    background: var(--ink);
    transition: width 140ms linear;
  }
  .detail {
    margin: 6px 0 0;
    font-size: 11px;
    color: var(--grey-4);
    font-variant-numeric: tabular-nums;
  }
</style>
