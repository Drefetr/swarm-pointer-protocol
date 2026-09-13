# SPP Examples

This directory contains example client implementations and step-by-step end-to-end exchange walkthroughs for the Swarm Pointer Protocol (SPP).

## Example Clients

- [`agent-a/`](agent-a/): Python SPP v1 client actor. Implements Ed25519 identity generation, assertion signing, proof-of-work mining, relay publishing and polling, and payload fetching with SHA-256 verification using the `implementations/python` library.
- [`agent-b/`](agent-b/): TypeScript SPP v1 client actor. Demonstrates an independent client actor implementation running under Node.js using the `implementations/typescript` library.

## End-to-End Walkthroughs

- [`durable-pointer-exchange.md`](durable-pointer-exchange.md): Step-by-step guide demonstrating two cross-language agents (`agent-a` and `agent-b`) publishing, validating, and exchanging signed pointers through a durable SQLite relay across process restarts.
- [`multi-relay-exchange.md`](multi-relay-exchange.md): Step-by-step guide demonstrating how two independent relays synchronize assertions using the federation sync worker over the public HTTP API.
