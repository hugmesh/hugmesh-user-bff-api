# Security — hugmesh-user-bff-api

## Authentication layers

Two independent layers defend this BFF.

1. **OAuth2 resource server (application layer).** Every route except the public
   list below needs a valid Casdoor-issued JWT
   (`spring.security.oauth2.resourceserver`) or an opaque `bff_` session, which
   `BffSessionAuthenticationWebFilter` turns into a server-built principal. The
   owner is always the JWT subject, and that scopes the owner-keyed
   profile/preference/block tables. The caller's bearer goes on to federation-api, so
   the owner check holds end to end (a `bff_` session is first exchanged for a
   custody JWT). `/bff/user/internal/**` accepts `ROLE_SERVICE` only.

   Public routes (`permitAll` in `SecurityConfig.commonRoutes`): `/actuator/health`,
   `/actuator/health/**`, `/actuator/info`, `/bff/login`, `/bff/register`,
   `/bff/session`, `/bff/sessionOut`, `/bff/register/google`, `/bff/register/discord`,
   `/bff/password-reset/request`, `/bff/password-reset/confirm`. The OpenAPI spec and
   Swagger UI are public under the `dev`/`test` profiles and need `ROLE_ADMIN` or
   `ROLE_SUPERADMIN` otherwise. The login, register and password-reset routes answer
   503 while their default-off flags stay off.

2. **Mutual TLS — the API-to-API trust boundary (transport layer).** In-cluster,
   the TLS handshake **requires a client certificate that chains to the cluster CA
   truststore**. Only services deployed and signed by our Vault/ESO PKI process hold
   such a certificate. A random pod, an `io`/external client, or anything not issued by
   our PKI presents no chaining cert. The server rejects its handshake before it
   reads any HTTP, so that caller cannot read or call this API at all.

## How the mTLS layer is wired

The cluster CA is the offline root from `hugmesh-generator/scripts/gen-keystores.sh`.
In-cluster, Vault PKI imports that CA and issues a short-lived leaf cert per app.
External Secrets Operator (ESO) syncs it into the `hugmesh-user-bff-api-mtls`
`kubernetes.io/tls` Secret (`tls.crt` / `tls.key` / `ca.crt`; the ExternalSecret is
in `hugmesh-generator` `specs/cluster/manifests/external-secrets/pki-externalsecrets.yaml`).
A keystore initContainer (the equivalent of the gateway chart's `build-keystore`) builds:

- `keystore.p12` — this service's own mTLS **identity** (key + cert chain),
- `truststore.p12` — the **cluster CA** trust anchor,

in an in-pod tmpfs (`/stores`, an `emptyDir` with `medium: Memory`). It also generates
the store password there; the password never enters git, a Secret, or Vault. The
initContainer writes the passwords to `/stores/application.properties`, which the app
loads through `SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/`. The password is not
an env var. The deployment sets the env below, and the running pod then enforces
client-cert verification. Every in-cluster leaf chains to the same cluster CA, so the
truststore validates them all. ESO rotates the cert before it expires.

The gateway (`hugmesh-fe-gateway`/`hugmesh-be-gateway`) is the legitimate
caller. It presents its own ESO-issued client cert when it proxies to this BFF, so
its handshake succeeds and everyone else's fails.

### Outbound direction

The BFF also presents its identity on outbound calls. `FederationHttpClientSsl`
builds a reactor-netty connector from the same `keystore.p12` and `truststore.p12`
(`hugmesh.mtls.client.*`, reusing the `SSL_*` env). It is off by default
(`HUGMESH_MTLS_CLIENT_ENABLED=false`). It covers the https peers: federation-api,
admin-bff `/bff/internal`, and the homeserver proxies on `:4443`. With the flag off,
those calls use the JDK default truststore, which does not hold the cluster CA.
The client store passwords come from `hugmesh.mtls.client.key-store-password` and
`hugmesh.mtls.client.trust-store-password`. Only the generator's initContainer writes
them into `/stores/application.properties`.

## Configuration (parameterized — safe by default)

`server.ssl.*` in `application.yml` takes its values from env, so local, dev and CI keep working:

| Property | Env var | Local/CI default | In-cluster value |
| --- | --- | --- | --- |
| `server.ssl.enabled` | `SSL_ENABLED` | `false` (plaintext) | `true` |
| `server.ssl.client-auth` | `SSL_CLIENT_AUTH` | `none` | `need` |
| `server.ssl.key-store` | `SSL_KEY_STORE` | `/stores/keystore.p12` | mounted PKCS12 keystore |
| `server.ssl.key-store-type` | `SSL_KEY_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.key-store-password` | `SSL_KEY_STORE_PASSWORD` | _(empty)_ | in-pod-generated, set in `/stores/application.properties` (the env var stays unset) |
| `server.ssl.trust-store` | `SSL_TRUST_STORE` | `/stores/truststore.p12` | mounted PKCS12 truststore (cluster CA) |
| `server.ssl.trust-store-type` | `SSL_TRUST_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.trust-store-password` | `SSL_TRUST_STORE_PASSWORD` | _(empty)_ | in-pod-generated, set in `/stores/application.properties` (the env var stays unset) |
| `server.ssl.enabled-protocols` | `SSL_ENABLED_PROTOCOLS` | `TLSv1.3` | `TLSv1.3` (the default; no manifest sets it) |

With the defaults, `server.ssl.enabled=false`, so the app never opens the stores and
existing tests run unchanged. `client-auth` maps to Netty's `ClientAuth`:
`none → NONE`, `want → OPTIONAL`, `need → REQUIRE`. WebFlux/Netty reads these
properties directly; the server side needs no custom `SslContext`/`HttpServer` bean.

## Deployment: shipped (dual-homed in this repo + hugmesh-generator)

The two manifests have drifted (see below). Enforcement is **already on** in both. The authoritative copy is the
one in `hugmesh-generator` (`specs/cluster/manifests/user-bff-api/deployment.yaml`).
A GitOps-pilot copy lives here in [`deploy/deployment.yaml`](deploy/deployment.yaml).
It was added for the Forgejo-cutover pilot; [`hugmesh-deploy.yaml`](hugmesh-deploy.yaml)
says the live ArgoCD ignores it and the generator copy stays authoritative.
The two agree on the server side, but they have drifted since. Only the generator copy
sets `HUGMESH_MTLS_CLIENT_ENABLED=true` and writes the `hugmesh.mtls.client.*`
passwords, and many other env values differ. Do not read `deploy/` as a
verbatim copy. Both manifests:

- add the `build-keystore` initContainer, plus the `pki` (from
  `hugmesh-user-bff-api-mtls`) and `stores` (tmpfs) volumes. They mirror the
  `build-keystore` initContainer in
  `specs/cluster/charts/hugmesh-gateway/templates/deployment.yaml` in `hugmesh-generator`.
- set:

```
SSL_ENABLED=true
SSL_CLIENT_AUTH=need
SSL_KEY_STORE=/stores/keystore.p12
SSL_KEY_STORE_TYPE=PKCS12
SSL_TRUST_STORE=/stores/truststore.p12
SSL_TRUST_STORE_TYPE=PKCS12
SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/
```

The two store passwords are not env vars. The initContainer generates them in the pod
and writes `server.ssl.key-store-password` and `server.ssl.trust-store-password` into
`/stores/application.properties`. Keep that file name. Spring loads a profile-named
file such as `application-tls.properties` only when that profile is active.

A plain `scheme: HTTPS` kubelet probe cannot present a client cert, and
`client-auth=need` rejects a cert-less handshake. So both manifests use an **HTTPS
exec probe** for readiness and liveness: `curl --cert/--key/--cacert` against
`/actuator/health/{readiness,liveness}`. The probe authenticates as this pod's own
mTLS identity. The gateway (`hugmesh-fe-gateway`/`hugmesh-be-gateway`) presents its
own ESO-issued client cert and calls this BFF over `https://`, or its proxied route
fails.
