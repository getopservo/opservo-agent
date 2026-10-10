# Contributing

Thanks for taking the time to help.

- **Bugs and ideas:** open a GitHub issue. Say what you ran, what you expected,
  and what happened. Agent logs (`journalctl -u infrapilot-agent`) help.
- **Security issues:** do not open an issue — see [SECURITY.md](SECURITY.md).
- **Pull requests:** keep them small and focused. Before opening one, run:

  ```bash
  go build ./...
  go vet ./...
  go test ./...
  ```

  New collectors or parsers need tests. Collectors must fail soft: if a probe
  cannot run on a host, report nothing for that field rather than an error or a
  guess.

Ground rules for agent code:

- The agent never reads application `.env` files or other app secrets.
- No new inbound ports. The agent only makes outbound HTTPS requests.
- Anything that changes the host (running commands, network probes) stays
  behind its existing switches and signature checks.

By contributing you agree that your contribution is licensed under the
Apache License 2.0.
