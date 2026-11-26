# Upstream provenance

Source: [KASPACOM/kaspa-covenants](https://github.com/KASPACOM/kaspa-covenants)

Imported commit: `2306f23cd3bacff4ead8d78477563697579a6057`

License: [MIT](LICENSE), copied unchanged with its copyright notice.

[upstream-files.json](upstream-files.json) records the SHA-256 of every imported
file before extraction changes. The six crates, migrations, fixtures, embedded
protocol assets and snapshot/archive tools are owned here. External public Cargo
dependencies remain pinned by the unchanged Cargo.lock.

## Extraction changes

- Cargo.toml repository metadata points here. Crate names and source bytes stay unchanged.
- Dockerfile.shadow-v2 gains Markets-indexer image metadata; the decoder revision
  remains an explicit build argument. `.dockerignore` retains embedded build assets.
- Local Compose, verification scripts and workflows belong to this repository.
- The imported runbook describes the V2 runtime. References to legacy commands
  are context; wallet settlement helpers and frontends are not shipped here.

`decoder-compatibility.txt` identifies the imported decoder behavior. A build's
source commit is independent of that compatibility revision. Do not substitute
this repository's HEAD into SHADOW_DECODER_REVISION. Change the compatibility
revision only with a reviewed decoder/seed compatibility decision.

Upstream changes must be reviewed and imported explicitly. There is no automatic
sync, submodule, private dependency or upstream checkout in builds.

## Original review references

- [Design #850](https://github.com/KASPACOM/kaspa-covenants/pull/850)
- [Implementation #851](https://github.com/KASPACOM/kaspa-covenants/pull/851)
- [Tests #852](https://github.com/KASPACOM/kaspa-covenants/pull/852)

These remain open as source references. Markets-indexer owns the replacement stack.
