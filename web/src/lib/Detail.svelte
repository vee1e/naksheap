<script lang="ts">
  import type { Node } from './types'

  interface Props {
    node: Node | null
  }

  let { node }: Props = $props()

  function hex(n: number) {
    return '0x' + n.toString(16)
  }
</script>

<aside class="panel">
  {#if !node}
    <p class="hint">select a node</p>
  {:else}
    <p class="addr">{hex(node.addr)}</p>
    <dl>
      <dt>type</dt>
      <dd>
        {node.ty.name}
        <span class="conf">{(node.ty.confidence * 100).toFixed(0)}%</span>
      </dd>

      <dt>state</dt>
      <dd>
        {node.state}
        {#if node.is_root}<span class="tag">root</span>{/if}
        {#if !node.reachable_from_root}<span class="tag">unreachable</span>{/if}
      </dd>

      <dt>size</dt>
      <dd>{node.size.toLocaleString()} B</dd>

      <dt>edges</dt>
      <dd>
        {node.inbound} in / {node.outbound} out
        {#if node.ty.members > 1}
          <span class="dim">· {node.ty.members} same layout</span>
        {/if}
      </dd>
    </dl>

    {#if node.ty.fields.length > 0}
      <h2>fields</h2>
      <table>
        <tbody>
          {#each node.ty.fields as f (f.offset)}
            <tr>
              <td class="off">+{hex(f.offset)}</td>
              <td>{f.kind}</td>
              <td class="dim">{f.hint ?? ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}

    {#if node.ty.evidence.length > 0}
      <h2>evidence</h2>
      <ul>
        {#each node.ty.evidence as e, i (i)}
          <li>{e}</li>
        {/each}
      </ul>
    {/if}
  {/if}
</aside>

<style>
  .panel {
    border: 1px solid var(--grey-2);
    padding: 14px;
    font-size: 12px;
    overflow: auto;
    min-width: 0;
  }
  .hint {
    color: var(--grey-4);
    margin: 0;
  }
  .addr {
    margin: 0 0 12px;
    font-size: 15px;
    font-variant-numeric: tabular-nums;
  }
  dl {
    display: grid;
    grid-template-columns: 60px 1fr;
    gap: 4px 10px;
    margin: 0;
  }
  dt {
    color: var(--grey-4);
  }
  dd {
    margin: 0;
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    align-items: baseline;
  }
  .conf {
    color: var(--grey-4);
    font-variant-numeric: tabular-nums;
  }
  .tag {
    border: 1px solid var(--grey-3);
    padding: 0 4px;
    font-size: 10px;
    color: var(--grey-5);
  }
  .dim {
    color: var(--grey-4);
  }
  h2 {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--grey-4);
    font-weight: 500;
    margin: 16px 0 6px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
  }
  td {
    padding: 1px 0;
    vertical-align: top;
  }
  .off {
    color: var(--grey-4);
    padding-right: 10px;
    white-space: nowrap;
    font-variant-numeric: tabular-nums;
  }
  ul {
    margin: 0;
    padding-left: 16px;
    color: var(--grey-5);
  }
  li {
    margin-bottom: 2px;
  }
</style>
