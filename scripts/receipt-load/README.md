# Receipt load harness

Build with `go build -o receipt-load ./scripts/receipt-load`, then run `./receipt-load --binary ./pipelock --out NEW_OUTPUT_DIRECTORY`. The harness drives a local proxy and sink, measures performance, and checks receipt evidence. Process measurements require Linux `/proc`; if it is unavailable during setup, the run exits `4`. `run.sh OUTPUT_DIRECTORY` builds both binaries and preserves the harness exit code; its own build/setup failures return `4`. `matrix.sh` records each cell's exact status in `scope.exit` and fails the matrix if any cell fails.

| Code | Meaning |
| --- | --- |
| 0 | Receipt integrity passed and performance was measured. |
| 1 | Receipt evidence failed, or the failure cannot safely be classified as setup-only. Missing, invalid, and unverifiable receipts use this code. |
| 2 | Invalid arguments or summary input. |
| 3 | Integrity passed, but performance measurement was invalid. |
| 4 | Harness setup failed before the workload could produce receipt evidence: output directory, binary, rules/config preparation, sink bind, proxy port/start/readiness, or sampler initialization. Lock acquisition failures also use this code. |

Every nonzero code is a failed run. Across modes, integrity failure takes precedence over harness failure, then performance failure. A failure after the workload starts retains code `1` when receipt integrity cannot be established; a later restart or verifier failure cannot be reclassified as setup-only. Setup errors still write failed verdicts to `result.json` when possible. If writing that result fails, classification fails closed with code `1`.
