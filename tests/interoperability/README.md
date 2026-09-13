# Interoperability

Two independently written §28 relays:

```text
python implementations/python/relay.py --port 18760
npx tsx implementations/typescript/src/relay.ts --port 18761
```

```text
python tests/interoperability/relay-tests/run_tests.py
python tests/interoperability/durable-e2e/run_tests.py
python tests/interoperability/multi-relay-e2e/run_tests.py
```

Application semantics stay out of scope. Relays validate with their own `spp-verify` stack and must not share a server framework. The multi-relay harness demonstrates that two independent durable relays can synchronize using only the ordinary public SPP client interface (`implementations/relay/federation/sync.py`).
