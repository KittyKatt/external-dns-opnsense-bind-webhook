# Agent notes

## Development environment

This repo builds with Go 1.22 (`go.mod` pins 1.22.2, toolchain 1.22.3).

The container has no root and no working `apk`, and `$HOME/.cache` is root-owned,
so there is no system Go. A toolchain can be installed non-destructively:

```bash
bash scripts/setup-go.sh
source /home/opencode/tools/go-env.sh
```

`scripts/setup-go.sh` downloads Go 1.22.12 from `go.dev/dl`, verifies its sha256,
extracts it to `$HOME/tools/go`, and redirects the build/module caches to
`$HOME/tools` (the default cache dir is unwritable here). It is idempotent — a
second run skips the download. `$HOME` is ephemeral, so reinstall after a
container restart (~1 min).

### Verifying changes

```bash
go build ./...    # passes
go test ./...     # see gotcha below
```

### Gotcha

`go vet` flags `internal/opnsense-bind/client.go:164`: a `log.Debugf` passing a
`map[string]APISelectOption` to `%s`. It is pre-existing and outside normal
changes; CI only runs `go build`, so it does not block the image build. The fix
is `%s` -> `%v`.
