# Workspace verification and packaging

The four sibling checkouts must contain the coordinated security changes. Use
Go **1.27.4**, a C compiler, Python **3.11+**, and Linux AMD64 or ARM64. Node uses
CGO. Cross-building Node requires the matching GNU cross compiler, for example
`gcc-aarch64-linux-gnu` on an AMD64 host.

Each module provides `./build/verify.sh [all|build|security|race|vuln]`. `build`
verifies dependencies, compiles all test binaries with vet using
`go test -exec /bin/true`, and builds commands. It does not execute legacy
integration tests or their initialization. `security` adds the selected security
race tests and `govulncheck`; `all` also builds commands. Native Linux AMD64 is
required for the race and vulnerability modes. The test selection fails if a
package has no selected tests. Set `EDGE_VERIFY_JOBS=2` to reduce build pressure.

Install the scanner with:

```sh
go install golang.org/x/vuln/cmd/govulncheck@v1.9.0
```

## Complete packages

From the directory containing `EdgeCommon`, `EdgeAPI`, `EdgeAdmin`, and
`EdgeNode`:

```sh
python3 EdgeCommon/build/package-workspace.py \
  --workspace . --output /tmp/edge-release-amd64 \
  --arch amd64 --node-arches amd64,arm64
```

The output directory must be new and outside the module checkouts. `--check`
prints the validated build plan without compiling. `--component node`, `api`, or
`admin` emits only that component's complete package; API/Admin include the Node
deployment ZIPs and installer helpers they need. Admin includes API and a separate
offline `edge-sign-release` executable. `--component node --arch arm64` builds
one Node archive. Only the community edition and Linux targets are supported.

The packager builds fresh binaries from private copies of Git-visible source
files, including local uncommitted fixes. It verifies module checksums, generates
Admin assets in the copy, rejects symlinks, and excludes live configuration,
credentials and runtime directories. It never uses an old `dist/` ZIP. Archive
names use each component's actual `Version` constant. Required nested files,
executable permissions and CRCs are checked before output publication.

`build-manifest-linux-ARCH.json` records source commit/working-tree snapshot
hashes, toolchain, compiler and artifact digests. `SHA256SUMS-linux-ARCH` covers
all emitted files. ZIP ordering, permissions and timestamps are fixed; set
`SOURCE_DATE_EPOCH` to the agreed release timestamp. Reproducing native binaries
also requires the same compiler, libc, architecture and dependency inputs.
The manifest describes a build; it is **not a publisher signature**. Sign the
final Admin ZIP offline following `EdgeAdmin/doc/signed-upgrades.md` before
publishing it for automatic upgrades. No private key is created or copied by
this packager.

## CI source pins

Publish the matching Common commit first, then configure these repository
variables with full 40-character commit hashes:

| Workflow repository | Required sibling refs |
| --- | --- |
| EdgeCommon | None |
| EdgeNode | `EDGE_COMMON_REF` |
| EdgeAPI | `EDGE_COMMON_REF`, `EDGE_NODE_REF` |
| EdgeAdmin | `EDGE_COMMON_REF`, `EDGE_API_REF`, `EDGE_NODE_REF` |

Publish Node and API commits before configuring Admin's refs. The workflows
intentionally fail when a ref is absent or malformed. Existing historical
Common commits do not contain these helpers and new authentication packages;
do not substitute an old commit just to satisfy the check. Pull requests have
read-only repository permissions; only the tag-release job has release write
permission. CI archives remain unsigned until the offline signing step.

## Existing source-generation scripts

The existing developer scripts remain available from `EdgeCommon/build/`:

- `./build-messages.sh` regenerates multilingual source files.
- `./build.sh` regenerates Go RPC stubs and `rpc.json` after changes to `.proto`
  files. It requires `protoc` plus the matching `protoc-gen-go` and
  `protoc-gen-go-grpc` plugins. Regenerate coordinated stubs across clients and
  servers when changing the protocol; the security/dependency upgrade does not
  require regeneration of the existing stubs.
- `./proto-json.sh` regenerates the RPC listing in `rpc.json`.

If a proto file is renamed, reconcile the generated files in `pkg/rpc/pb/`
before regeneration so stale definitions are not retained.
