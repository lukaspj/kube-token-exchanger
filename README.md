# kube-token-exchanger

Kubernetes operator that exchanges Kubernetes ServiceAccount identity tokens for
authentik identity tokens via the OAuth2 **client credentials** grant with a
JWT client assertion ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).

Requirements:

- authentik **2026.8 or later** (Kubernetes ServiceAccount JWT client assertion support)
- Kubernetes cluster
- Go 1.26+ (build only)

## How it works

1. A `TokenExchangeRequest` describes a ServiceAccount, an authentik OAuth2
   provider, and a target Secret.
2. The operator mints a short-lived, audience-bound ServiceAccount token via
   the TokenRequest API.
3. It presents that JWT as `client_assertion` to authentik's token endpoint
   (`POST /application/o/token/`, `grant_type=client_credentials`,
   `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`).
4. authentik verifies the JWT signature against the registered federated OIDC
   source (the cluster's JWKS) and returns an identity token.
5. The operator writes the token to the target Secret and re-requests it
   before expiry (default refresh window: 30s before expiry).

```
ServiceAccount ──TokenRequest──> operator ──client_credentials──> authentik
                                                        │
      workload <──Secret (auto-rotated) <───────────────┘
```

No client secret is configured anywhere. The cluster's identity is proven by
the ServiceAccount JWT itself; a stolen secret cannot be replayed after the
token expires, and authentik trusts the token only if signed by the
registered Kubernetes API server key.

## Authentik setup

Configured in the authentik admin interface. authentik 2026.8 or later is
required.

### 1. Register the Kubernetes cluster as an OAuth source

authentik must be able to verify the ServiceAccount JWT signature. Create a
generic **OAuth source** (Directory > Federation & Social login):

- Set the source type to a generic OIDC/OAuth source.
- **JWKS URL / OIDC discovery**: point it at the cluster API server, e.g.
  - OIDC discovery: `https://kubernetes.default.svc/.well-known/openid-configuration`
  - or JWKS URI: `https://kubernetes.default.svc/openid/v1/jwks`
- authentik must be able to reach this URL (same cluster or via ingress/
  load balancer) and must trust the API server's serving certificate.

The Kubernetes API server signs ServiceAccount tokens with an issuer of
`https://kubernetes.default.svc` (unless `--service-account-issuer` is
overridden). The `audience` configured on the operator's
`TokenExchangeRequest` objects must be accepted by the cluster's
`--service-account-issuer`/`--api-audiences` flags and match what the source
in authentik expects.

### 2. Create the OAuth2 provider

Create an **OAuth2/OpenID Provider** (Applications > Providers):

1. Under **Grant Types**, enable **Client credentials** (disable the grant
   types the provider does not need).
2. Bind the provider to an **Application**.
3. Under **Machine-to-Machine authentication settings > Federated OIDC
   Sources**, select the Kubernetes source created in step 1.

Note the provider's `client_id`. A client secret is not needed; leave it
unset and do not distribute it to clusters.

### 3. Map the Kubernetes identity to an authentik user

On a successful request authentik automatically creates a service account
derived from the provider name and the JWT's `sub` claim
(`system:serviceaccount:<namespace>:<name>` for Kubernetes tokens) and issues
the access token for that account.

To propagate claims from the Kubernetes token into the issued token, create
an **OAuth Source Property Mapping** to copy incoming JWT values onto the
generated account, then an **OAuth2 Scope Mapping** to include them as claims
on issued tokens:

```python
# OAuth Source Property Mapping
return {
    "attributes": {
        "kubernetes_subject": info.get("sub"),
        "kubernetes_namespace": info.get("kubernetes.io", {}).get("namespace"),
    },
}
```

```python
# OAuth2 Scope Mapping
return {
    "kubernetes_namespace": request.user.attributes.get("kubernetes_namespace"),
}
```

### 4. Restrict access (optional but recommended)

Expression policies bound to the application can limit which ServiceAccounts
may obtain tokens. The parsed JWT is available as
`request.context["oauth_jwt"]`:

```python
return request.context["oauth_jwt"]["iss"] == "https://kubernetes.default.svc"
```

Other context: `request.context["oauth_scopes"]` (requested scopes) and
`request.context["oauth_grant_type"]`.

### 5. Configure the operator

Point the operator at the provider's client ID:

```sh
--authentik-url=https://authentik.example.com
--authentik-client-id=<provider client_id>
```

No `--authentik-client-secret*` flag exists anymore; authentication happens
exclusively via the ServiceAccount JWT client assertion.

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
  targetSecret:
    name: my-workload-authentik-token
```

The authentik connection (URL, client ID, scopes, TLS settings) is configured
on the operator via flags — see `--authentik-*` — not on the request.
Workloads carry no provider credentials; their identity comes solely from the
Kubernetes ServiceAccount token presented as the client assertion.

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
- No authentik credentials are stored in the cluster. The only credential
  used against authentik is the short-lived, audience-bound ServiceAccount
  token, minted per request and never persisted.
- Tokens never appear in logs or events; only expiry timestamps are logged.

## Development

```sh
make generate   # regenerate deepcopy, CRD, RBAC
make build
make test
make vet
make run        # run locally against current kubeconfig
```
