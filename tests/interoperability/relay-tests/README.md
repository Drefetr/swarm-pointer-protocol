# Relay tests

Requires green `conformance/diff_verify.py` and `conformance/mutate_diff.py`.

```text
python interoperability/relay-tests/run_tests.py
```

Starts `impl-a/relay.py` and `impl-b/src/relay.ts` on distinct ports and exercises:

```text
channel description → pointer → retrieve
capability / unlisted channel
object index
pagination
duplicate submission
local PoW multiplier
policy rejection
missing parents
relay-to-relay scrape
invalid JSON rejection
```

Cross-submit is bidirectional. Scrape follows §29 advertised public surface only.
