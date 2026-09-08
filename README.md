# kube-token-exchanger

Kubernetes operator that exchanges Kubernetes ServiceAccount identity tokens for
authentik identity tokens via [RFC 8693 token exchange](https://datatracker.ietf.org/doc/html/rfc8693).

Requirements:

- authentik **2026.8 or later** (token-exchange grant support)
- Kubernetes cluster
- Go 1.26+ (build only)

## How it works

1. A `TokenExchangeRequest` describes a ServiceAccount, an authentik OAuth2
   provider, and a target Secret.
2. The operator mints a short-lived, audience-bound ServiceAccount token via
   the TokenRequest API.
3. It presents that JWT as `subject_token` to authentik's token endpoint
   (`POST /application/o/token/`, `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
4. authentik verifies the JWT through the registered federated OIDC source and
   returns an identity token.
5. The operator writes the token to the target Secret and re-exchanges it
   before expiry (default refresh window: 30s before expiry).

```
ServiceAccount ──TokenRequest──> operator ──token exchange──> authentik
                                                        │
      workload <──Secret (auto-rotated) <────────────────┘
```

## Authentik setup

1. Create an **OAuth2/OpenID Provider** (Applications > Providers) and under
   **Grant Types** enable **Token exchange**.
2. Bind the provider to an Application.
3. Register the Kubernetes API server as a trust source so authentik can verify
   the subject token: under the provider's **Machine-to-Machine authentication
   settings**, add an OIDC source pointing at the cluster:
   - Issuer URL: `https://kubernetes.default.svc`
   - JWKS URI: `https://kubernetes.default.svc/openid/v1/jwks`
4. Map the Kubernetes identity to an authentik user. The token exchange
   resolves the `sub` claim of the ServiceAccount token
   (`system:serviceaccount:<namespace>:<name>`) to an authentik user via the
   provider's subject mode and scope mappings; configure them to map the
   desired ServiceAccounts.
5. Note the provider's `client_id` and `client_secret`.

The `audience` of the minted ServiceAccount token is configurable per
`TokenExchangeRequest` and should match the audience configured on the OIDC
source in authentik.

## Install

```sh
kubectl apply -k config/
```

Or build and push your own image:

```sh
IMG=registry.example.com/kube-token-exchanger:latest make docker-build docker-push
```

## Usage

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: authentik-oauth2-client
  namespace: default
type: Opaque
stringData:
  client-id: "<provider client_id>"
  client-secret: "<provider client_secret>"
---
apiVersion: tokenexchange.aldershaab-it.dk/v1alpha1
kind: TokenExchangeRequest
metadata:
  name: my-workload
  namespace: default
spec:
  serviceAccount:
    name: my-workload
  audience: https://authentik.example.com
  tokenLifetime: 5m          # optional, default 5m
  refreshWindow: 30s         # optional, default 30s
  authentik:
    url: https://authentik.example.com
    clientId:
      name: authentik-oauth2-client
      key: client-id
    clientSecret:
      name: authentik-oauth2-client
      key: client-secret
    scopes: [openid, email]
  targetSecret:
    name: my-workload-authentik-token
```

### Private key JWT client authentication

Instead of a shared `client_secret`, the operator can authenticate itself to
authentik with a freshly minted Kubernetes ServiceAccount token presented as a
`client_assertion` (RFC 7523 JWT bearer). authentik validates it through the
same Kubernetes API server trust source used for `subject_token` JWTs.

```yaml
spec:
  authentik:
    url: https://authentik.example.com
    clientId:
      name: authentik-oauth2-client
      key: client-id
    clientAuthMethod: privateKeyJwt
    clientAssertionServiceAccount:
      name: token-exchanger            # SA in the operator's namespace
      namespace: kube-token-exchanger
    # clientAssertionAudience: client-id  # optional, defaults to the client ID
```

No `clientSecret` is required in this mode; the field is ignored. The operator
needs `serviceaccounts/token` create permission on the assertion
ServiceAccount (already granted cluster-wide by the bundled RBAC).

The target Secret contains:

| Key | Content |
|---|---|
| `token` | authentik access token |
| `expiresAt` | RFC3339 expiry |
| `scope` | granted scopes |
| `issuedTokenType` | issued token type |
| `audience` | ServiceAccount token audience |
| `serviceAccount` / `serviceAccountNamespace` | source identity |

Mount it in a workload:

```yaml
volumes:
  - name: authentik-token
    secret:
      secretName: my-workload-authentik-token
      items:
        - key: token
          path: token
```

The operator rotates the token before expiry; kubelet propagates Secret updates
to mounted volumes automatically.

## Status

```sh
kubectl get tokenexchangerequests -n default
kubectl describe tokenexchangerequest my-workload -n default
```

`status.conditions` reports `Ready` with reasons `TokenIssued`, `ExchangeFailed`
or `InvalidSpec`. Failures also emit Kubernetes Events.

## Metrics

Exposed on `:8080`:

- `tokenexchange_exchanges_total{namespace,name,result}`
- `tokenexchange_exchange_duration_seconds{namespace,name}`
- `tokenexchange_token_ttl_seconds{namespace,name}`

## Security notes

- The operator's ServiceAccount is granted `create` on `serviceaccounts/token`
  and Secret write access cluster-wide. Bind the ClusterRole only in clusters
  where the operator is trusted; consider restricting the RoleBinding if a
  namespace-scoped deployment is preferred.
- Client credentials are read from the referenced Secrets on every exchange, so
  rotation of the authentik client secret requires no restart.
- Tokens never appear in logs or events; only expiry timestamps are logged.

## Development

```sh
make generate   # regenerate deepcopy, CRD, RBAC
make build
make test
make vet
make run        # run locally against current kubeconfig
```
