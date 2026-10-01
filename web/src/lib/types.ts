// Mirrors the JSON that `naksheap-wasm` emits (see crates/naksheap-wasm/src/lib.rs
// and crates/naksheap-inference/src/types.rs). Kept deliberately close to the
// Rust shapes so a change on either side shows up as a type error here.

export type Stage = 'parse' | 'carve' | 'scan' | 'infer' | 'serialize'

export interface Progress {
  stage: Stage
  done: number
  total: number
  fraction: number
}

export type ObjectState = 'allocated' | 'freed' | 'mmap' | 'unknown'

export type ObjectLabel =
  | 'probable_struct'
  | 'opaque_buffer'
  | 'freed_chunk'
  | 'zero_region'
  | 'std_string'
  | 'vector'
  | 'vtable_object'

export type FieldKind = 'pointer' | 'vtable' | 'string' | 'integer' | 'bytes'

export interface Field {
  offset: number
  kind: FieldKind
  /** Human-readable target, e.g. "-> 0x7faa00002f00". Null when not applicable. */
  hint: string | null
}

export interface ObjectType {
  name: string
  label: ObjectLabel
  confidence: number
  evidence: string[]
  size: number
  members: number
  fields: Field[]
}

export interface Node {
  addr: number
  size: number
  state: ObjectState
  ty: ObjectType
  inbound: number
  outbound: number
  reachable_from_root: boolean
  is_root: boolean
}

export interface GraphEdge {
  from: number
  to: number
  offset: number
  confirmed: boolean
  source: string
}

export interface Stats {
  total_objects: number
  allocated: number
  freed: number
  mmap: number
  clusters: number
  root_reachable: number
  edges: number
  confirmed_edges: number
  max_depth: number
}

export interface Meta {
  format: string
  process: string | null
  command_line: string | null
  exec_path: string | null
  pointer_width: number
  threads: number
  truncated: boolean
  input_bytes: number
  objects: number
  edges: number
  roots: number
}

export interface MapRange {
  start: number
  end: number
  file_offset: number
  file_size: number
  perms: { read: boolean; write: boolean; execute: boolean }
  kind: 'file' | 'anon' | 'unknown'
  path: string | null
  name: string | null
}

export interface AnalyzeResult {
  graph: {
    version: string
    stats: Stats
    arenas: unknown[]
    nodes: Node[]
    edges: GraphEdge[]
    roots: unknown[]
  }
  meta: Meta
  maps: MapRange[]
}

export interface WorkerIn {
  bytes: ArrayBuffer
}

export type WorkerOut =
  | { type: 'progress'; progress: Progress }
  | { type: 'done'; result: AnalyzeResult }
  | { type: 'error'; message: string }
