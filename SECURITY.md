# Security policy

## Reporting a vulnerability

Please email **hello@getopservo.com** with "Security" in the subject line.
Do not open a public GitHub issue for security problems.

Include what you can:

- the affected version or commit,
- steps to reproduce, or a proof of concept,
- what an attacker could do with it.

We will acknowledge your report, keep you updated while we fix it, and credit
you in the release notes if you would like.

## Scope

This repository contains the agent that runs on monitored servers and
Kubernetes clusters. Issues in the hosted Opservo service (getopservo.com) can
be reported to the same address.

Of particular interest:

- anything that lets a party other than the operator run commands on a host,
- bypasses of the Ed25519 signature checks on updates, commands or probe
  assignments,
- the agent sending secrets, file contents or unmasked personal data to the API.
