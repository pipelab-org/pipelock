# Receipt v3 conformance

The receipt v3 gate runs every vector against installed verifier packages. The Go and WebAssembly lanes use the `full` profile and compare `projection.json`. The TypeScript, Rust and Python lanes use `v3-core` and compare `projection.core.json` when present, falling back to `projection.json` otherwise. The gate also checks exit codes, legacy detection and result stability across file order.

Core verifiers return `USE_HOST_VERIFIER` for mixed old-format and v3 evidence. Use `pipelock verify-receipt --chain <dir>` to verify the full directory. The Go reference test generates the core projections from the same corpus and checks each committed projection.
