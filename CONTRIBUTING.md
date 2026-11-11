# Contributing to actp

Thanks for helping. Bug reports, fixes, docs and new agent presets are all welcome.

## Before you start

- **Bugs:** open an issue with the "Bug report" form. Include `actp version`, your OS, the agent, and the lines from `~/.actp/logs/actp.log` around the problem. Remove tokens first.
- **Security problems:** do not open an issue. See [SECURITY.md](.github/SECURITY.md).
- **Bigger changes:** open an issue first, so we can agree on the approach before you write code. The design is in [`docs/design.md`](docs/design.md); behaviour changes should update it.

## Development

You need Go 1.25 or newer.

```bash
go test -race ./...
```

```bash
go vet ./...
```

- **HTTP API:** change [`api/openapi.yaml`](api/openapi.yaml), then run `go generate ./api/` and commit the generated code. CI fails if it is stale.
- **Wire format:** servers must keep accepting `actp.v1` for all of actp 1.x (see [`docs/wire.md`](docs/wire.md)). Add fields; do not change the meaning of existing ones.
- **Tests:** behaviour belongs in an end-to-end test in [`internal/e2e`](internal/e2e), which runs a real bridge, server and the scripted agent in [`internal/testagent`](internal/testagent). Drop and freeze tests go through the TCP proxy in the test harness.
- **Agent presets:** add the preset in [`internal/config/presets.go`](internal/config/presets.go) and the facts in [`docs/agents.md`](docs/agents.md), with the version you checked it against.
- **Tray:** build with `-tags tray`. On macOS, `packaging/macos/build-app.sh` builds `actp.app`.

## Pull requests

- Keep each PR to one change, with a clear description of what and why.
- Run `gofmt`, `go vet` and the tests before you push. CI runs them on Linux, macOS and Windows.
- Update the docs and the README when you change something users see.

By contributing, you agree that your work is licensed under the [Apache 2.0 license](LICENSE), and you agree to follow the [code of conduct](CODE_OF_CONDUCT.md).
