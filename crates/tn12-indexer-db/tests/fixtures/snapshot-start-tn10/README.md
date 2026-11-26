# TN10 snapshot start regression

Public REST transaction fixtures captured on 2026-10-09 from
`https://api-tn10.kaspa.org/transactions/{txid}?inputs=true&outputs=true&resolve_previous_outpoints=light`.

`start.json` is transaction
`14f3ae9175b08628266cd1ebdba28be216264c3792acbdc461f90bc8beb164d8`,
accepted at blue score 579934265. The parent files establish its bootstrap
and controller outputs.

The start transaction creates the token genesis reserve at output 0 and the
controller continuation at output 1. Both bind to input 1. Counting every
output with that authorizing input as a controller successor stalled both
the live watcher and REST repair worker.
