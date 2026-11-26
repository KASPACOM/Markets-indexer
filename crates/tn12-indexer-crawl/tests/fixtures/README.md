# Live writer backlog fixtures

Captured from DEV TN10 on 2026-10-01 after the live writer exhausted its 768 MiB memory limit while notifications accumulated.

`live-oom-transactions.json` contains 16 transaction records reconstructed from public REST transaction metadata for IDs in the slow writer sample. Input prevout script, amount, and address are absent, matching the live RPC conversion before cache resolution. Acceptance coordinates are assigned by each test.

`live-oom-parents.json` contains the corresponding public parent IDs, timestamps, and outputs. These are reduced parent records, not complete RPC notifications. Parent timestamps were between 1790884169032 and 1790884174456 milliseconds; the observed child acceptance was 1790884175159. This fixture proves cached-output resolution and persistence semantics. It does not prove all parents will be cached in a live workload or establish live throughput.

The database test uses synthetic acceptance blocks and a local isolated database. It compares scalar and bulk state, counts update statements, replays duplicates, and reverts the child block.
