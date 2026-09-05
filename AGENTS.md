# AGENTS.md

## Build commands

- `make generate` — regenerate deepcopy, CRD, RBAC (must rerun after ANY change to `api/v1alpha1/tokenexchangerequest_types.go` or RBAC kubebuilder markers in `internal/controller/`)
- `make build` / `make test` / `make vet`
- `make manifests` — render manifests (`kubectl kustomize config`); also a good smoke test for config validity
- `make run` — run operator locally with leader election against current kubeconfig

## Sandbox / environment quirks (non-negotiable)

- This machine runs inside a nono sandbox:
  - The default Go module cache under `$HOME/go` is NOT readable. Export before any go/kubectl-adjacent command:
    `export GOMODCACHE=/tmp/opencode/gomod GOSUMDB=off`
  - Loopback TCP connects are BLOCKED (`dial tcp 127.0.0.1: connect: permission denied`). Do NOT use `httptest.NewServer` or any test that binds/listens on TCP. Tests must inject a custom `http.RoundTripper` (see `internal/authentik/client_test.go` fakeTransport pattern). The controller tests use `sigs.k8s.io/controller-runtime/pkg/client/fake` (no network) — user-required approach for integration tests.
  - If a filesystem op fails with EPERM, diagnose with `nono why --path <path> --op read|write`; do NOT suggest sudo/chmod.

## Codegen gotchas (controller-tools v0.22)

- Both markers REQUIRED on the package doc in `api/v1alpha1/groupversion_info.go`, or the CRD group is empty and deepcopy generates nothing:
  `// +groupName=tokenexchange.aldershaab-it.dk`
  `// +kubebuilder:object:generate=true`
- RBAC markers live in `internal/controller/tokenexchangerequest_controller.go`; `make generate` reads them from there.
- `hack/tools.go` pins controller-gen so it survives `go mod tidy`.
- In `config/kustomization.yaml`, resources must be explicit FILES. A directory entry like `crd/bases` fails kustomize build (it looks for a kustomization.yaml inside). Keep: `crd/bases/tokenexchange.aldershaab-it.dk_tokenexchangerequests.yaml`.

## Architecture

- Namespace-scoped CRD `TokenExchangeRequest` (`tokenexchange.aldershaab-it.dk/v1alpha1`), cluster-scoped operator in namespace `kube-token-exchanger`.
- Flow: controller mints SA token (TokenRequest API, `internal/kubernetes`) → RFC 8693 token exchange at authentik (`internal/authentik`) → writes target Secret → requeues at expiry−refreshWindow for rotation.
- authentik endpoint: `POST {url}/application/o/token/`, form-encoded, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt` (K8s SA tokens are JWTs).
- Authentik must be >= 2026.8 and have the K8s API server registered as federated OIDC source (issuer `https://kubernetes.default.svc`, JWKS `.../openid/v1/jwks`).
- `main.go`: import collision — `k8s.io/client-go/kubernetes` aliased as `internalKubernetes` vs `internal/kubernetes` package.
- Project is NOT a git repo; no CI, no linter config beyond `go vet`.
