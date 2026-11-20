<!-- Copyright (c) Microsoft Corporation.
Licensed under the MIT License. -->

# AGENTS.md

Blip runs commands in VMs backed by durable `BlipState` workspaces. A `Blip` is
one execution of one command; deleting it saves and releases its writable
filesystems. The controller, node agent, VM runtime, guest agent, CLI, and chat
UI live under `cmd/` and `internal/`.

## Repository requirements

- **Copyright headers.** Every first-party source, script, config, and doc file
  starts with the header defined in `hack/headers.py` (Go files use
  `hack/boilerplate.go.txt`). Run `make headers` after adding files and
  `make verify-headers` before finishing. JSON files are exempt because JSON
  has no comment syntax. Never remove existing third-party notices; never add
  a Microsoft header to third-party code.
- **LICENSE.** Do not change the top-level `LICENSE` copyright notice; CELA owns
  that decision.
- **GitHub Actions.** Pin every `uses:` reference to a full 40-character commit
  SHA with a `# vX.Y.Z` comment. Run `make verify-actions`.
- **Generated files.** Do not hand-edit `api/v1alpha1/zz_generated.deepcopy.go`
  or `deploy/crd/*.yaml`. Change the API, then run `make generate`.
- **Template files.** Keep `SECURITY.md`, `CODE_OF_CONDUCT.md`, and `SUPPORT.md`
  aligned with the Microsoft repository template.
- **Verification.** Run `gofmt -l .`, `go vet ./...`, `go test ./...`,
  `make verify-headers`, and `make verify-actions`. Do not run `gofmt -w` on
  `api/v1alpha1/types.go`; it would rewrite a CEL rule. Run `make test-sim`
  when changing simulation or concurrent adapter code.

## Working style

Follow existing package patterns and tests. Keep diffs focused and add tests for
behavior changes. Avoid new dependencies and unrelated refactors.
