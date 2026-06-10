# Security — snapdragon-user-bff-api

## Authentication layers

This BFF is defended in depth by two independent layers:

1. **OAuth2 resource server (application layer).** Every request must carry a
   valid Casdoor-issued JWT (`spring.security.oauth2.resourceserver`); owner==JWT-
   subject enforcement scopes the owner-keyed profile/preference/block tables. The
   caller's bearer is forwarded to federation-api for end-to-end owner enforcement.
   This is unchanged.

2. **Mutual TLS — the API-to-API trust boundary (transport layer).** In-cluster,
   the TLS handshake **requires a client certificate that chains to the cluster CA
   truststore**. Only services that were deployed and signed by our Vault/ESO PKI
   process hold such a certificate. A random pod, an `io`/external client, or
   anything not issued by our PKI presents no chaining cert, so its handshake is
   rejected before any byte of HTTP is read — it cannot read or call this API at all.

## How the mTLS layer is wired

The cluster CA is the offline root from `snapdragon-generator/scripts/gen-keystores.sh`.
In-cluster, Vault PKI imports that CA and issues a short-lived leaf cert per app;
External Secrets Operator (ESO) syncs it into the `snapdragon-user-bff-api-mtls`
`kubernetes.io/tls` Secret (`tls.crt` / `tls.key` / `ca.crt`). A keystore
initContainer (the equivalent of the gateway chart's `build-keystore`) assembles:

- `keystore.p12` — this service's own mTLS **identity** (key + cert chain),
- `truststore.p12` — the **cluster CA** trust anchor,

into an in-pod tmpfs and generates the store password there (it never enters git,
a Secret, or Vault). The deployment then sets the env below so the running pod
enforces client-cert verification. Because every in-cluster leaf chains to the same
cluster CA, the truststore validates them; ESO rotates the cert before expiry.

The gateway (`snapdragon-fe-gateway`/`snapdragon-be-gateway`) is the legitimate
caller: it presents its own ESO-issued client cert when proxying to this BFF, so
its handshake succeeds while everyone else's fails.

## Configuration (parameterized — safe by default)

`server.ssl.*` in `application.yml` is parameterized so local/dev/CI keep working:

| Property | Env var | Local/CI default | In-cluster value |
| --- | --- | --- | --- |
| `server.ssl.enabled` | `SSL_ENABLED` | `false` (plaintext) | `true` |
| `server.ssl.client-auth` | `SSL_CLIENT_AUTH` | `none` | `need` |
| `server.ssl.key-store` | `SSL_KEY_STORE` | `/stores/keystore.p12` | mounted PKCS12 keystore |
| `server.ssl.key-store-type` | `SSL_KEY_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.key-store-password` | `SSL_KEY_STORE_PASSWORD` | _(empty)_ | in-pod-generated |
| `server.ssl.trust-store` | `SSL_TRUST_STORE` | `/stores/truststore.p12` | mounted PKCS12 truststore (cluster CA) |
| `server.ssl.trust-store-type` | `SSL_TRUST_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.trust-store-password` | `SSL_TRUST_STORE_PASSWORD` | _(empty)_ | in-pod-generated |
| `server.ssl.enabled-protocols` | `SSL_ENABLED_PROTOCOLS` | `TLSv1.3` | `TLSv1.3` |

With the defaults, `server.ssl.enabled=false`, so the stores are never opened and
existing tests run unchanged. `client-auth` maps to Netty's `ClientAuth`:
`none → NONE`, `want → OPTIONAL`, `need → REQUIRE`. WebFlux/Netty reads these
properties directly; no custom `SslContext`/`HttpServer` bean is needed.

## Deployment requirement (owned by snapdragon-generator)

The deployment manifest for this BFF lives in `snapdragon-generator`
(`specs/cluster/manifests/user-bff-api/deployment.yaml`), not in this repo. To
turn enforcement on, that deployment must (a) add the keystore initContainer +
`pki` (from `snapdragon-user-bff-api-mtls`) and `stores` (tmpfs) volumes —
exactly as `charts/snapdragon-gateway/templates/deployment.yaml` does — and (b) set:

```
SSL_ENABLED=true
SSL_CLIENT_AUTH=need
SSL_KEY_STORE=/stores/keystore.p12
SSL_KEY_STORE_TYPE=PKCS12
SSL_KEY_STORE_PASSWORD=<in-pod generated>
SSL_TRUST_STORE=/stores/truststore.p12
SSL_TRUST_STORE_TYPE=PKCS12
SSL_TRUST_STORE_PASSWORD=<in-pod generated>
```

The readiness/liveness probes must switch to HTTPS (`scheme: HTTPS`) once
`SSL_ENABLED=true`, and the gateway must present its client cert AND call this BFF
over `https://` for the route to keep working.
