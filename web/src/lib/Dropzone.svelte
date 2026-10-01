<script lang="ts">
  // Drop target + file picker. The only thing this component does with the
  // file is hand the bytes to the worker; nothing is uploaded, which is the
  // whole reason the analyzer ships as wasm.
  import type { Meta } from './types'

  interface Props {
    busy: boolean
    onfile: (file: File) => void
    onsample: () => void
    meta: Meta | null
  }

  let { busy, onfile, onsample, meta }: Props = $props()

  let dragging = $state(false)
  let input: HTMLInputElement

  function accept(file: File | undefined | null) {
    if (!file || busy) return
    onfile(file)
  }

  function onDrop(e: DragEvent) {
    e.preventDefault()
    dragging = false
    accept(e.dataTransfer?.files?.[0])
  }
</script>

<div class="drop" class:dragging class:busy>
  <input
    bind:this={input}
    type="file"
    onchange={(e) => accept(e.currentTarget.files?.[0])}
    accept=".core,application/octet-stream"
    hidden
  />
  <p class="lead">drop a core dump</p>
  <p class="sub">
    elf64 x86-64 or aarch64, or a 64-bit windows minidump. nothing is uploaded: the
    analyzer runs in this tab.
  </p>
  <div class="actions">
    <button onclick={() => input.click()} disabled={busy}>choose file</button>
    <button onclick={onsample} disabled={busy} class="ghost">use the sample</button>
  </div>
  {#if meta}
    <p class="meta">
      {meta.process ?? 'unknown process'}
      <span class="dim">·</span>
      {meta.format}
      <span class="dim">·</span>
      {meta.threads}
      {meta.threads === 1 ? 'thread' : 'threads'}
      <span class="dim">·</span>
      {(meta.input_bytes / 1048576).toFixed(1)} MiB
    </p>
  {/if}
</div>

<svelte:window
  ondragover={(e) => {
    e.preventDefault()
    dragging = true
  }}
  ondragleave={() => (dragging = false)}
  ondrop={onDrop}
/>

<style>
  .drop {
    border: 1px dashed var(--grey-3);
    padding: 28px 24px;
    text-align: center;
    transition: border-color 120ms ease, background 120ms ease;
  }
  .drop.dragging {
    border-color: var(--ink);
    background: var(--grey-1);
  }
  .drop.busy {
    opacity: 0.5;
    pointer-events: none;
  }
  .lead {
    margin: 0 0 6px;
    font-size: 15px;
  }
  .sub {
    margin: 0 0 16px;
    color: var(--grey-4);
    font-size: 12px;
    max-width: 46ch;
    margin-inline: auto;
  }
  .actions {
    display: flex;
    gap: 8px;
    justify-content: center;
  }
  .meta {
    margin: 14px 0 0;
    font-size: 12px;
    color: var(--grey-5);
  }
  .dim {
    color: var(--grey-3);
    padding: 0 2px;
  }
</style>
