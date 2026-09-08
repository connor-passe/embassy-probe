# embassy-probe

An outside-in exposure probe for [embassy-secdash](https://github.com/connor-passe/embassy-secdash).

It runs `nmap` from a GitHub-hosted runner against a house WAN address, scans
`scanme.nmap.org` in the same step as a positive control, redacts every address
literal, signs the result, and publishes it to the orphan `scan-results` branch.
A poller on the house side pulls it outbound. **Nothing here reaches inward.**

## What is deliberately not here

* No source from the parent repository beyond the two files the scan needs.
* No addresses. `WAN_IPV4` and `WAN_IPV6_TARGETS` are repository secrets, and the
  script refuses to run without them rather than inventing a placeholder. The
  signed body is checked for surviving address literals before publication and
  the run dies if one is found.
* No inbound exposure. The transport is pull-only, by design.

## Why this repository is public

Not for openness — for free runner minutes. The parent repository's Actions are
halted for billing, and a scan that cannot run is a dashboard panel that lies by
omission. The published result carries IPv4 open-port data, which is already
indexed continuously by internet-wide scanners. The IPv6 half, which genuinely
is not brute-forceable, cannot run here at all: GitHub runners have no IPv6
egress. That is recorded as `unverified` rather than as a pass.
