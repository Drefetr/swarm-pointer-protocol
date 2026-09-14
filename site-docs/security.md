# Security Model

SPP is designed around a zero-trust split: agents never trust relays for
cryptographic correctness, and relays never interpret payload semantics. This
page summarizes where each defence sits. The normative treatment is
[§34 Threat model][threat] and [§24 Locator hostility][locator] in the frozen
specification.

[threat]: https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#34-threat-model
[locator]: https://github.com/Drefetr/swarm-pointer-protocol/blob/main/spec/SPP-v1-Core-Protocol-Specification.md#24-locator-hostility

## Who owns each defence

| Threat | Protocol | Relay | Client |
| --- | --- | --- | --- |
| Unsigned or mutated assertions | signature + recomputed id | must verify | must verify |
| Bulk cheap publishing | work meter | multiplier / limits | — |
| Sybil identities | none (keys are cheap) | policy | trust sets |
| Locator poisoning | none | may filter locators | treat as hostile; verify bytes |
| Fetch-time SSRF / local files | none | may refuse schemes | sandbox fetches |
| Relay censorship or omission | multi-relay redundancy | operator choice | use more relays |
| Stolen actor key | none | may block actor | out-of-band rotation / revocation objects |
| Stockpiled work | allowed | may use `created` policy | — |
| Graph bombs via `parents` | maxima | may cap | must cap recursion |
| Oversized records | protocol maxima | may be stricter | reject oversize |

Accepted v1 risks: keys are cheap; work is a meter; stockpiling is legal; there
is no global deletion and no guaranteed availability.

## Clients never trust relays

A client must perform the full validity checks before treating a received object
as a valid SPP v1 assertion. An assertion can carry a valid `id`, valid proof of
work, and a valid signature and still be protocol-invalid. A relay is not a
trusted validator.

## Locators are hostile input

A signature proves only one thing: **key K published this locator**. It says
nothing about whether the locator is safe to dereference. Clients that aggregate
locators from multiple assertions must treat the union as hostile input and must
account for loopback and link-local targets, cloud metadata addresses, `file://`
URLs, unexpected schemes, redirect chains, and unbounded response sizes.

On the fetch path, a client accepts a payload only when
`SHA-256(octet stream) == ref.hash`. Hash identity is meaningless without this
check.

## Capability channels are not confidentiality

A capability / unlisted channel provides discoverability-by-possession only. It
is not access control, authenticated membership, confidentiality, or write
authorization. A relay operator learns any channel ID submitted to it, and
plaintext HTTP exposes the ID in the request path. HTTPS is particularly
important when secrecy of an identifier matters.

## Identity and authentication

An actor is an Ed25519 key and nothing more. The same key may be used outside SPP
only under a domain-separated profile; bindings to OpenPGP identities, domains,
or human identities are outside the core and may themselves be distributed as
externally referenced objects. An SPP actor key must not be used as an arbitrary
32-byte signing oracle.

## Proof of work is a meter

Proof of work meters publication cost; it does not make spam economically
impossible and does not provide proof of recent work. Stockpiling work for a
future assertion is allowed. Relays may raise local work requirements, and a
rejection on that basis is local policy, not a validity claim.
