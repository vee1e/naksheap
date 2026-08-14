# fixtures

Generated artifacts, not hand-edited sources.

| File | Contents |
|---|---|
| toy-server.core | A deterministic synthetic ELF64 core dump |
| toy-server.core.manifest.json | The ground-truth manifest for that core: arenas, objects, roots, edges |

Regenerate from the repo root:

```sh
cargo run -p naksheap-testkit --example gen_fixture -- fixtures
```

The build is byte-for-byte deterministic. This golden core guards against regressions in the parser, carver, and scanner.
