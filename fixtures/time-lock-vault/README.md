# Time Lock Vault Debug Fixtures

This directory is the first local SilverScript debugger baseline for the KASPACOM TN12 Time Lock Vault work.

- `time-lock-vault.webwallet.sil` is the source extracted from the web wallet `origin/tn-12` template.
- `time-lock-vault-tx-time.debug.sil` isolates the `tx.time >= timeout` branch without Schnorr signatures, so the upstream debugger can prove TX-context behavior immediately.
- `time-lock-vault-tx-time.debug.test.json` defines passing and failing TX lock-time scenarios for `cli-debugger`.

Run:

```bash
SILVERSCRIPT_DIR=~/silverscript ../../scripts/run-timelock-fixture.sh
```

Interactive example:

```bash
cd ~/silverscript
cargo run -p cli-debugger -- \
  /path/to/tn12-covenant-tools/fixtures/time-lock-vault/time-lock-vault-tx-time.debug.sil \
  --test-file /path/to/tn12-covenant-tools/fixtures/time-lock-vault/time-lock-vault-tx-time.debug.test.json \
  --test-name recovery_after_timeout_passes
```

The real `time-lock-vault.webwallet.sil` still needs a signed transaction fixture or live `kascov` trace before it can pass through the debugger end to end.

Observed debugger caveat:

- `tx.time` parses in the special time-lock statement form `require(tx.time >= timeout);`.
- `tx.time` does not currently parse as a normal expression in `console.log(...)` or local assignment.
- Use `tx.locktime` for normal expression inspection when that is sufficient, but keep `tx.time` for the real time-lock opcode path.
