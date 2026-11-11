#!/usr/bin/env bash
# Shared by the four sibling repositories. Source this file from build/verify.sh.

verify_linux_amd64() {
  if [[ "$(go env GOHOSTOS)/$(go env GOHOSTARCH)" != linux/amd64 ||
        "$(go env GOOS)/$(go env GOARCH)" != linux/amd64 ]]; then
    printf '%s\n' 'Race and vulnerability checks require native Linux AMD64; use build mode for cross builds.' >&2
    return 1
  fi
}

verify_compile() {
  go mod verify
  # Compile every test and run vet without executing legacy tests/package init,
  # which may open real services, databases or external network connections.
  go test -p "$verify_jobs" -tags=community -exec /bin/true ./...
}

verify_build() {
  mkdir -p "$verify_tmp/bin"
  if [[ "$verify_module_name" == EdgeCommon ]]; then
    go build -p "$verify_jobs" -trimpath -tags=community ./...
  else
    go build -p "$verify_jobs" -trimpath -tags=community -o "$verify_tmp/bin/" ./cmd/...
  fi
}

verify_run_race() {
  verify_sequence=$((verify_sequence + 1))
  local log_file="$verify_tmp/race-$verify_sequence.log"
  printf '%s\n' "Running race regressions: $*"
  if go test -p "$verify_jobs" -tags=community -race -v -count=1 -timeout=180s "$@" >"$log_file" 2>&1; then
    :
  else
    local result=$?
    cat "$log_file"
    return "$result"
  fi
  # A renamed/deleted test must not turn a security gate into a green no-op.
  if grep -Eq 'no tests to run|\[no test files\]' "$log_file" ||
       ! grep -q '^--- PASS:' "$log_file"; then
    cat "$log_file"
    printf '%s\n' 'Security regression selection did not execute the required tests.' >&2
    return 1
  fi
  awk '/^ok[[:space:]]/ || /^--- SKIP:/ { print }' "$log_file"
}

verify_race() {
  case "$verify_module_name" in
    EdgeCommon)
      verify_run_race ./pkg/rpcauth ./pkg/healthcheck
      verify_run_race ./pkg/serverconfigs -run '^TestSecurity'
      verify_run_race ./pkg/configutils ./pkg/rpc/pb \
        -run '^(TestYAMLNodeConfigLegacyInteroperability|TestLegacyNodeStreamWireCompatibility|TestGeneratedNodeRPCCompatibility)$'
      ;;
    EdgeAPI)
      verify_run_race ./internal/passwords ./internal/utils/principals ./internal/utils/cryptoutils \
        ./internal/rpc/utils ./internal/db/models ./internal/rpc/services ./internal/setup ./internal/tasks \
        -run '^(TestSecurity|TestValidateRoleSubject)'
      verify_run_race ./internal/utils/securefs ./internal/configs ./internal/instances ./cmd/edge-instance-installer \
        -run '^TestSecurity'
      ;;
    EdgeAdmin)
      verify_run_race ./internal/csrf ./internal/utils/upgradesecurity \
        ./internal/utils/securefs ./internal/web/actions/default/index/loginutils \
        ./internal/web/actions/default/files ./internal/web/actions/default/csrf
      verify_run_race ./internal/rpc ./internal/utils ./internal/web/actions/actionutils ./internal/web/helpers \
        -run 'Test(RPCTransportRequiresVerifiedTLSOrExplicitMigration|RPCTransportLoopbackModeRejectsExternalHTTPAndDNS|AdminContextsUseBoundSignedClaims|UpgradeTransportRejectsUntrustedCertificateAndRedirects|UpgradeMetadataReadIsBounded|CSRFHelperRejectsCrossSessionAndReplay|StoreAdminDoesNotPublishPartiallyPersistedSession|SecurityRandomTokensPreserveFormatAndDoNotRepeat)$'
      ;;
    EdgeNode)
      verify_run_race ./internal/httpcache ./internal/delivery
      verify_run_race ./internal/nodes ./internal/stats ./internal/rpc \
        ./internal/utils/counters ./internal/utils/expires ./internal/waf \
        ./internal/waf/requests ./internal/waf/checkpoints ./internal/waf/injectionutils \
        -run '^Test(Security|ApplyMaxCPU|AccessLog|PermanentAccessLog|TrafficUploadPreservesStructured|RequestBodyCheckpoint|RequestFormArgCheckpoint|RequestJSONArgCheckpoint|RequestUploadCheckpoint|ResponseBodyCheckpoint|WAFManager_convert|WAF_MatchRequest|DetectSQLInjection$)'
      verify_run_race ./internal/caches ./internal/utils/kvstore -run '^Test(DependencyUpgrade|Security(Cache|FileReader|OpenFile))'
      verify_run_race ./internal/utils/mem
      verify_run_race ./internal/compressions -run '^TestSecurity'
      verify_run_race ./internal/configs ./internal/utils -run '^TestSecurityNode'
      verify_run_race ./internal/utils -run '^TestSimpleEncrypt'
      ;;
  esac
}

verify_vuln() {
  local scanner
  scanner="$(command -v govulncheck || true)"
  if [[ -z "$scanner" ]] ||
       ! go version -m "$scanner" | grep -Eq '^[[:space:]]*mod[[:space:]]+golang.org/x/vuln[[:space:]]+v1\.9\.0[[:space:]]'; then
    printf '%s\n' 'Install the pinned scanner: go install golang.org/x/vuln/cmd/govulncheck@v1.9.0' >&2
    return 1
  fi
  case "$verify_module_name" in
    EdgeCommon) "$scanner" -tags=community ./... ;;
    EdgeAPI) "$scanner" -tags=community ./cmd/edge-api ./cmd/installer-helper ./cmd/installer-dns-helper ./cmd/edge-instance-installer ;;
    EdgeAdmin) "$scanner" -tags=community ./cmd/edge-admin ./cmd/edge-sign-release ;;
    EdgeNode) "$scanner" -tags=community ./cmd/edge-node ;;
  esac
}

verify_module() (
  local verify_module_name="$1"
  shift
  local mode="${1:-all}"
  if [[ $# -gt 1 ]]; then
    printf '%s\n' 'Usage: build/verify.sh [all|build|security|race|vuln]' >&2
    exit 2
  fi
  case "$mode" in
    all|build|security|race|vuln) ;;
    *) printf '%s\n' 'Usage: build/verify.sh [all|build|security|race|vuln]' >&2; exit 2 ;;
  esac
  export GOTOOLCHAIN=local
  export GOFLAGS="${GOFLAGS:-} -mod=readonly"
  if [[ "$(go env GOVERSION)" != go1.27.4 ]]; then
    printf '%s\n' 'Go 1.27.4 is required; select it in PATH before verification.' >&2
    exit 1
  fi
  if [[ "$(go list -m)" != "github.com/TeaOSLab/$verify_module_name" ]]; then
    printf '%s\n' "Verification must run in the $verify_module_name module." >&2
    exit 1
  fi
  local verify_jobs="${EDGE_VERIFY_JOBS:-4}"
  if [[ ! "$verify_jobs" =~ ^[1-9][0-9]*$ ]]; then
    printf '%s\n' 'EDGE_VERIFY_JOBS must be a positive integer.' >&2
    exit 2
  fi
  if [[ "$mode" != build ]]; then verify_linux_amd64; fi
  local verify_tmp
  verify_tmp="$(mktemp -d "${TMPDIR:-/tmp}/edge-module-verify.XXXXXXXX")"
  trap 'rm -rf -- "$verify_tmp"' EXIT
  local verify_sequence=0
  printf '%s\n' "Verifying $verify_module_name ($mode) with Go 1.27.4"
  case "$mode" in all|build|security) verify_compile ;; esac
  case "$mode" in all|build) verify_build ;; esac
  case "$mode" in all|security|race) verify_race ;; esac
  case "$mode" in all|security|vuln) verify_vuln ;; esac
)
