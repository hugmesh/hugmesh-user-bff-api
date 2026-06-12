# snapdragon-user-bff-api

Spring **user BFF** — the `ROLE_USER`-floor backend-for-frontend paired with the
(later) `snapdragon-user-ui`. Reactive WebFlux + R2DBC + Liquibase + Casdoor JWT
resource-server + springdoc + Spring Native, scaffolded from the
`snapdragon-admin-bff-api` template (same stack, same conventions). Java 21,
Spring Boot 3.5.5.

## Where it sits

A **backend-namespace BFF** — deployed into `snapdragon-backend`, reached only
*behind the gateway*, never public. It is the per-role backend-for-frontend for
ordinary users, the `ROLE_USER` peer of `snapdragon-admin-bff-api` (admin) and the
mod BFF. It is **JWT-only / post-login**: there is no `/login` or `/register` here
(the admin-bff owns registration); every request must carry a valid Casdoor token.
It talks to:

- **Casdoor** (the IdP) as an OAuth2 resource server — validates the JWT, and is
  the destination for the self-service password/email change.
- **snapdragon-federation-api** — for the caller's federation **cards** (bundles)
  and the instance-block **recommendation** chain (caller JWT forwarded per request).
- the **homeservers** (tuwunel / Matrix, Akkoma / Mastodon) **through the gateway
  mTLS proxies** — for the external block push, self-silence visibility hides,
  connected-client list/revoke, and the AI-cloak media upload. These legs are
  **gated stub-seams** that never hard-fail (see *Honest deferrals*).

## The core invariant: owner-enforcement

**Every endpoint operates ONLY on the caller's OWN data.** The owner is ALWAYS the
Casdoor **JWT subject** (`jwt.getSubject()`) — never a path or request-body field. A
user can never read/write another user's profile, preferences, cards, blocks,
self-silence, or connected clients. There is deliberately no `/profile/{userId}`
style route; the only data a caller can address is their own, identified by the
token. The request body's `userId` is ignored on writes (always overwritten with the
JWT subject) so it cannot redirect a write to another user. This is enforced in
EVERY service method and tested at both the service layer (spoofed body, owner+id
scoped delete) and the repository/SQL layer (owner isolation).

## API surface (all under `/bff/user/**`, `ROLE_USER` floor, owner-enforced)

### Profile — `ProfileController` (`/bff/user/profile`)
Own R2DBC `user_profile` table (one row per user; `user_id` = JWT subject = PK).
Fields: `gender, pronouns, timezone, displayName, visibility {public|internal}
(default internal), vanitySubdomainEnabled, vanityUsername, screenReaderName`.

- `GET /bff/user/profile` — my profile (an empty default if none yet).
- `PUT /bff/user/profile` — create/update my profile (body `userId` ignored; the
  vanity username is derived from the **token** — `preferred_username`, then `name`,
  then subject — NOT the body, so the reserved-name guard can't be bypassed).
- `DELETE /bff/user/profile` — delete my profile.
- `POST /bff/user/profile/password` — change my **Casdoor** password.
- `POST /bff/user/profile/email` — change my **Casdoor** email.

Password + email are owned by the **Casdoor IdP**, not this BFF — they go through
a reactive `CasdoorUserClient` (the BFF never stores credentials). See deferrals.

**`displayName` + vanity-username guard** — charset/confusable-checked on every save
(zero-width / bidi / Cyrillic look-alike / reserved-confusable rejected with 400;
`@SafeDisplayName` + the ICU4J `UsernameSkeleton` + `ReservedNames` engine). The
skeleton is a recomputable defence-in-depth cache, never a DB identity — the exact
UNIQUE + the 004 `vanity_username` CHECK remain the DB backstop.

**`screenReaderName` (a11y)** — the ASCII-only aria-label / spoken name a screen
reader announces (`@SafeScreenReaderName` + the `ScreenReaderNames` engine; 008
`screen_reader_name` column). When `displayName` is pure **ASCII** the screen-reader
name **defaults** to it (no prompt); when `displayName` is **non-ASCII** an ASCII
screen-reader name is **required** — a save without one is a **422** the
registration/profile-save flow uses to prompt. A present non-ASCII screen-reader name
is a 400. (The aria-label UI consumption is a later UI-wave task — this carries the
field + validation + default/prompt logic.)

### Home-guide preference — `HomeGuideController` (`/bff/user/home-guide`)
Per-user "getting-started guide dismissed" flag, keyed per guide, stored in the
own R2DBC `user_preference` table as `home-guide-dismissed:<guide>` = `true`. The
role home views read this to show the welcome/getting-started guide only on first
visit.

- `GET  /bff/user/home-guide?guide=<g>` — `{guide, dismissed}` (default guide `home`).
- `POST /bff/user/home-guide/dismiss?guide=<g>` (and `PUT` alias) — dismiss.
- `DELETE /bff/user/home-guide/dismiss?guide=<g>` — re-show (un-dismiss).

### Cards — `CardsController` (`/bff/user/cards`)
CRUD over the caller's OWN federation bundles (`user_modules` in
`snapdragon-federation-api`), via the reactive `FederationApiClient`. The caller's
JWT is **forwarded per request** so federation-api scopes `/bundles/mine` (and
records bundle ownership on PUT) to the same subject — owner-enforcement holds
end-to-end with no broader service credential.

- `GET /bff/user/cards` → federation `GET /api/federation/bundles/mine`.
- `GET /bff/user/cards/{slug}` → federation `GET /api/federation/bundles/slug/{slug}`.
- `PUT /bff/user/cards/{slug}` (octet-stream) → federation `PUT /api/federation/bundles/{slug}`.

### Self-block + recommend-instance-block — `BlockController` (`/bff/user`)
Own R2DBC `user_block` table (`user_id, target, platform {matrix|mastodon|internal},
ts`).

- `GET /bff/user/blocks` — my self-blocks.
- `POST /bff/user/blocks` — record a durable block row (under me) **then**
  best-effort push the external mute/block to Matrix/Mastodon (STUBBED — see
  deferrals). The row is the source of truth even if the push is stubbed/fails.
  **PLATFORM-ROLE GATED:** a `matrix` block requires `ROLE_MATRIX`, a `mastodon`
  block requires `ROLE_MASTODON` (an `internal` block needs only the `ROLE_USER`
  floor) — a principal that does not hold the platform's access role cannot push an
  external mute to a homeserver it has no access to.
- `DELETE /bff/user/blocks/{id}` — remove one of my blocks (scoped by owner AND id).
- `POST /bff/user/recommend-instance-block` — start the **USER → MOD → ADMIN**
  instance-block chain via federation `POST /api/federation/moderation`
  (`kind=instance-block`; federation sets `status=recommended` server-side). This
  is a *recommendation*, not a self-block, and requires a homeserver platform role
  (`ROLE_MATRIX` OR `ROLE_MASTODON`).

The platform-role gate is **two-leg defence-in-depth**: a method-level
`@PreAuthorize` (SpEL on the validated request-body `platform`) is the API leg;
`BlockService` re-checks the SAME platform role against the caller's authorities
(service leg) so the rule holds even if a caller reaches the service by another path.
`ROLE_MATRIX`/`ROLE_MASTODON` map automatically via the Casdoor authorities
converter — no converter change.

### Self-silence — `SelfSilenceController` (`/bff/user/self-silence`)
Self-service **visibility hide** — a user makes THEMSELVES invisible to others for a
bounded window while keeping their own full session/access. It is **NOT a ban**: this
surface is structurally incapable of writing a Casdoor role, an `access_suspension`
row, or a revocation key — login/home stays normal for the silenced user. Own R2DBC
`self_silence` table (006; `expires_at` authoritative; a `@Scheduled`
`SelfSilenceExpiryAction` auto-clears at expiry).

- `POST /bff/user/self-silence/activate` — hide me until `expiresAt` (REQUIRED,
  must be in the FUTURE; `reason` optional). I keep my session + full access.
- `GET  /bff/user/self-silence/status` — my current silence (active or cleared).
- `POST /bff/user/self-silence/cancel` — un-silence myself now (un-hide + clear).
- `POST /bff/user/self-silence/email-mod` — ask a mod/admin to reactivate me sooner
  (writes a self-silence-appeal moderation request; NOT SMTP).

The homeserver localpart used for the visibility-hide seams comes from the JWT
`preferred_username` claim. All three hide legs are **gated stub-seams that never
hard-fail**: the federation user-scope hide-profile apply/clear leg
(`self-silence.federation.enabled`) and the homeserver directory/discovery hides
(`external.matrix.enabled` / `external.mastodon.enabled` — tuwunel
exclude-from-directory, akkoma `discoverable=false`) are all OFF by default; the
durable `self_silence` row stands regardless.

### Connected apps & devices — `ConnectedClientsController` (`/bff/user/connected-clients`)
The caller's native OAuth apps (Element / Tusky / Ivory) + device sessions registered
against the homeservers (akkoma / Matrix) **through the gateway passthrough**. Own
R2DBC `connected_client_audit` table (`owner, platform {matrix|mastodon}, client_kind
{oauth-app|device}, external_ref, label, created_at, revoked_at`; 009). The live
homeserver sessions are listed/revoked via the homeserver client API **through the
mTLS proxy** (a GATED stub-seam, never hard-fail); the audit row is the BFF-owned
durable record.

**EXTERNAL-CLIENT-ROLE GATE** — this surface requires an external-client role
(`ROLE_MATRIX_EXTERNAL_CLIENT` / `ROLE_MASTODON_EXTERNAL_CLIENT`), which is **separate**
from the base `ROLE_MATRIX` / `ROLE_MASTODON` our-UI access: the external-client role
gates whether a user may register/use a **native** client. Class-level `@PreAuthorize`
(API leg, at least one external-client role to reach the surface at all) + a
per-platform service re-check (service leg) so a matrix-only caller cannot revoke a
mastodon client and vice-versa. The roles map automatically via the Casdoor
authorities converter — no converter change.

- `GET /bff/user/connected-clients` — my connected apps + device sessions.
- `DELETE /bff/user/connected-clients/{id}` — revoke one of mine: write the
  **per-credential** gateway revocation key `hs:<platform>:<localpart>:<appId|deviceId>`
  first (`RevocationWriter`), best-effort homeserver delete, then stamp `revoked_at`.

Removing the external-client role → `ConnectedClientsService.reconcilePersonalClient
Revocation` writes `external-client:<localpart>:<platform>` (the gateway filter checks
it only for `kind=personal` tokens, so base our-UI access is unaffected).

### AI-cloak media proxy — `MediaPoisonController` (`/bff/user/media`)
The **poison-before-ingest** seam. The UIs route uploads through this BFF endpoint
**instead of POSTing media directly to the homeserver**, so the AI-cloak
(Glaze-style cloak / Nightshade-style poison) happens *before* any homeserver sees
the bytes, owns **every served size**, and the decision is recorded **server-side**
(`media_poison_decision` = audit + badge + repost source of truth). The prior
direct-to-homeserver path could do none of those — async-after-ingest is placebo
(re-encode strips perturbation, server thumbnails regenerate clean, federation wins
the race).

- `POST /bff/user/media/upload` — multipart (`file` + `platform {matrix|mastodon}` +
  `mode {glaze|nightshade|light|none}` + `roomId`/`description`). **Flow:** sniff the
  bytes (magic-byte, never the client `Content-Type`) → for an image with `mode!=none`
  and a **present** worker, call the poisoner **sync within a latency budget** to cloak
  the **original + every pinned served size** (akkoma `small`; Matrix `240x240`) → do
  the **real homeserver upload of the POISONED bytes** via the mTLS proxy → run the
  **round-trip survival gate** → return the homeserver `media_id`/`mxc` **exactly as
  the homeserver would** (UI compose logic untouched) plus a `cloak` block
  (`status/mode/backend/mediaRef`). Non-image / `mode=none` / feature-off → forwarded
  **through unchanged** (`status=none`).
- `GET /bff/user/media/capability` — worker backend (`cuda|rocm|cpu|none`) + offered
  modes + ETA, so the composer renders an **honest** shield state up front (incl.
  `Unavailable` when the heavy tier is absent).
- `GET /bff/user/media/status/{ref}` — my decision for a media ref (badge polling),
  owner-scoped.

**Round-trip survival gate (the badge never lies):** after the upload the service
re-fetches the served original + thumbnails and runs a perturbation-presence check;
it persists `protected` **only if it survived**, else `degraded`. **Honest copy:**
*"AI-cloak applied"*, never *"protected"* unless the gate passes — best-effort
training-set hygiene (removable by re-encode/downscale), not a guarantee.
**Uncloseable (stated honestly):** already-federated copies + native-client
(Element/Tusky) uploads that skip this BFF entirely.

**Lean fallback (k8s protocol-probe, no heavy tier):** the worker is the **optional**
x86/GPU `snapdragon-media-poisoner`. On a Pi5-only cluster its pod stays `Pending`,
its Service has no Ready endpoints, the `/health` probe reports `backend=none`, and
`app.media.poisoning.fallback-mode` decides: `skip` (default — forward **uncloaked**
with `status=skipped` + a documented signal so the UI warns *"not cloaked"*), `light`
(reduced-strength CPU if offered), or `queue` (placeholder-then-replace). Posting is
never *forced* to block. Ships **dark** by default (`app.media.poisoning.enabled
=false` ⇒ the controller is mounted but every upload forwards through `status=none`)
until the survival gate is verified on a real GPU cluster.

## Where data lives (the routing rule)

| Concern | Destination |
| --- | --- |
| Profile fields (incl. screenReaderName), home-guide prefs, self-block rows, self-silence rows, media-poison decisions, connected-client audit | **own R2DBC tables** (`user_profile`, `user_preference`, `user_block`, `self_silence`, `media_poison_decision`, `connected_client_audit`) |
| Password / email change | **Casdoor IdP** (`CasdoorUserClient`) — never stored here |
| Cards (federation bundles) + instance-block recommendation + (later) self-silence federation hide | **snapdragon-federation-api** (reactive `FederationApiClient`, forwarded JWT) |
| External mute/block push, self-silence directory hide, connected-client list/revoke, media upload | **Matrix (tuwunel)** / **Mastodon (Akkoma)** clients via the gateway mTLS proxy (STUBBED/gated) |
| Homeserver-token revocation keys | **gateway revocation list** (`RevocationWriter`, gated stub-seam until the gateway write endpoint ships) |

## Clients

- `FederationApiClient` — reactive WebClient of federation-api. Base URL
  `FEDERATION_API_BASE_URL` (default
  `http://snapdragon-federation-api.snapdragon-backend.svc.cluster.local:8080`).
  A token-injecting `ExchangeFilterFunction` re-injects the caller's JWT from the
  reactive security context as `Authorization: Bearer <jwt>` on every outbound
  call (`FederationWebClientConfig`).
- `CasdoorUserClient` — reactive WebClient for self-service password/email
  (`/api/set-password`, `/api/update-user`). Gated by `casdoor.account.enabled`.
- `MatrixBlockClient` / `MastodonBlockClient` — reactive WebClients for the
  external self-block push. Base URLs grounded in the snapdragon-generator
  manifests: tuwunel `:8008` (`MATRIX_URL`), Akkoma `:4000` (`MASTODON_URL`).
  Gated by `block.matrix.enabled` / `block.mastodon.enabled`.
- `MatrixHideClient` / `MastodonHideClient` — reactive WebClients for the
  self-silence directory/discovery hide seams. Gated by `external.{matrix,mastodon}
  .enabled`.
- `MatrixClientsClient` / `MastodonClientsClient` — reactive WebClients for the
  connected-clients list/revoke against the homeserver client API (through the mTLS
  proxy). `RevocationWriter` writes the gateway per-credential revocation keys.
- `PoisonWorkerClient` / `HomeserverMediaClient` — the media-proxy worker call +
  the real homeserver upload/re-fetch through the akkoma-proxy / tuwunel-proxy mTLS
  proxies (`app.media.proxy.{matrix,mastodon}.*`).

## Security — defence in depth

`SecurityConfig` is a Casdoor OAuth2 resource server (`issuer-uri` from
`CASDOOR_ISSUER_URI`). The JWT→authority converter is the **verbatim** Casdoor
converter from `snapdragon-admin-bff-api` / the gateway: `ROLE_USER` floor on every
authenticated principal; `roles` (string or `{name}`) → `ROLE_<UPPER>`;
`permissions` verbatim; `isAdmin` → `ROLE_ADMIN`. `@EnableReactiveMethodSecurity`
+ `@PreAuthorize` on the controllers re-checks at the method (the `ROLE_USER` floor,
plus the per-surface platform / external-client role gates above).
Profile/spec gating is profile-split: under `dev`/`test` the OpenAPI spec + Swagger
UI are public (so `gen:fetch` can curl `/v3/api-docs` tokenless); in prod they need
`ROLE_ADMIN`. Actuator health/info are public for probes.

### API-to-API mTLS (PKI identity, both directions)
In-cluster the deployment mounts a PKCS12 keystore (this service's Vault-PKI
identity) + truststore (the cluster CA) and flips on **server-side** client-auth
(`server.ssl.enabled=true`, `client-auth=need`, TLSv1.3 floor): a caller that was
not deployed+signed by our Vault/ESO PKI process holds no chaining cert and its TLS
handshake is rejected before it can read or call the API at all. The **client-side**
half (`snapdragon.mtls.client.enabled`, `FederationHttpClientSsl`) presents this
BFF's client identity on its OUTBOUND federation-api calls when federation-api flips
its server-side client-auth to `need`. Both reuse one mounted `/stores` layout.
Defaults keep local/dev/CI plaintext (`SSL_ENABLED=false`, client-auth `none`).

### Multi-tenancy / domain-scoping (on `feat/domain-foundation`, not yet on `main`)
The platform is multi-brand: one Casdoor per brand, so a token's
cryptographically-validated `iss` claim is the trustworthy tenant discriminator. The
`feat/domain-foundation` branch threads issuer-keyed domain-scoping through this BFF
to match the gateway. **Intent (on the branch):**

- The JWT→authority mapping moves to a shared `CasdoorAuthorities` converter COPIED
  (logic) from the gateway so the BFF and gateway emit **byte-identical** authorities.
  It stamps exactly one issuer-derived `DOMAIN_<x>` authority (resolved through a
  `DomainRegistry` issuer→domain map; unknown issuer → `default`), and **strips any
  `permissions` entry carrying a reserved `ROLE_`/`DOMAIN_` prefix** — those
  authorities come ONLY from controlled logic (roles claim / validated issuer), so a
  brand-X token cannot inject `permissions:["DOMAIN_brandy"]` (forged tenant) or
  `permissions:["ROLE_SUPERADMIN"]` (forged super-role) to escalate cross-domain.
- A single-issuer cluster (today's default) resolves `DOMAIN_default` for every
  token and nothing else changes (back-compat). When `app.tenancy.issuers` is
  populated, an optional multi-issuer decoder (`TenancyResourceServerConfig`) 401s
  an unknown `iss` before authorities are emitted (fail-closed).
- `PrincipalDomain` turns the validated JWT into the effective scope: **SUPERADMIN**
  (the cross-domain infra super-role) → `null` = unscoped (sees/mutates every
  brand's rows); any other principal → its concrete issuer-derived domain (a
  non-SUPERADMIN with an unresolvable issuer fails closed to a non-matchable
  `__deny__` sentinel).
- The data layer adds a per-query `domain` predicate (`DomainScope`: `AND domain =
  :domain`, or NO predicate for the SUPERADMIN bypass) **alongside** — never
  replacing — the existing `owner = :uid` predicate. The 010 changelog adds a
  back-compat `domain varchar(64) default 'default'` column (+ owner+domain indexes)
  to every owner-keyed table. A non-SUPERADMIN principal must satisfy BOTH owner AND
  domain. The domain is never read from a request field — only from the issuer — so a
  caller cannot forge a cross-tenant scope.

## Stack

Reactive WebFlux everywhere (Mono/Flux, reactive WebClient; no `.block()` /
`Thread.sleep` on the event loop). R2DBC for all runtime data; JDBC only for the
Liquibase migrations (`db/changelog`, 001–009 on `main`; +010 domain-scoping on the
branch). Spring Native: `native` profile + native-maven-plugin, surefire `argLine
-Dnet.bytebuddy.experimental=true`, `NativeHintsConfig` with reflection hints for the
JSON-bound DTOs + swagger-ui webjar resource hints. `R2dbcConvertersConfig` maps
Postgres/H2 timestamp types → `Instant` deterministically (JVM + native).

## Build / test

- `./mvnw test` — green. Coverage: the Casdoor authorities converter; ROLE_USER +
  spec role-gating (`@WebFluxTest`); repository slices over H2-PG-compat with the
  REAL Liquibase changelog (`TestDatabaseConfig`); **owner-enforcement**
  (`ProfileService` ignores a spoofed body userId; `BlockService` unblock is
  owner+id-scoped; repo slices assert owner isolation at the SQL layer); the
  platform-role / external-client-role gates; the username/displayName confusable +
  reserved-name + screen-reader-name guards; the self-silence distinctness
  (no role/suspension/revocation) + round-trip; the media-proxy sniff/poison/survival
  flow; the home-guide dismiss round-trip; the federation / Casdoor / Matrix /
  Mastodon clients + the JWT-forwarding filter against a mocked `ExchangeFunction`;
  and a full-context load test. (`feat/domain-foundation` adds the domain-scope
  repo/service/converter tests.)
- `./mvnw package -DskipTests` — builds the runnable jar.
- `./mvnw -Pnative native:compile` — GraalVM native binary (needs a GraalVM host).

CI is **GitLab only** (`.gitlab-ci.yml`); the GitHub repo is pull-mirrored into
in-cluster GitLab. There are deliberately **no `.github/workflows`** (GitHub
Actions is billing-blocked).

## Honest deferrals

- **External Matrix / Mastodon block push is STUBBED.** The clients implement the
  documented shapes (Matrix `PUT .../account_data/m.ignored_user_list`; Mastodon
  `GET /api/v1/accounts/lookup` then `POST /api/v1/accounts/{id}/block`) and the
  reactive flow is fully wired, but the live call is gated OFF by default
  (`block.{matrix,mastodon}.enabled=false`) because it needs the **owning user's**
  per-platform access token (broker via the admin-bff `ServiceTokenBroker`), which
  is out of scope here. When disabled the durable `user_block` row still stands
  and the response carries `external: "stubbed"`. Validate the payloads + token
  brokering against the deployed tuwunel/Akkoma before flipping the flag.
- **Self-silence hide seams are STUBBED.** The durable `self_silence` row + the
  `@Scheduled` auto-clear at `expires_at` are real and authoritative; the federation
  user-scope hide-profile leg and the homeserver directory/discovery hides are gated
  OFF (`self-silence.federation.enabled`, `external.{matrix,mastodon}.enabled`) and
  the real admin verbs are pinned against the deployed servers later.
- **Connected-clients homeserver list/revoke is a gated stub-seam.** The BFF-owned
  `connected_client_audit` row + the gateway per-credential revocation key
  (`RevocationWriter`) are the real enforcement; the live homeserver delete is
  best-effort and the gateway revocation-write endpoint ships later.
- **Casdoor password/email change is STUBBED by default** (`casdoor.account.enabled
  =false`). The reactive `CasdoorUserClient` flow runs end-to-end (controller →
  service → client) and acks `casdoor: "stubbed"`; the exact Casdoor payload +
  per-user auth (caller's own session vs. a service credential, and the
  `send-verification-code`/`verify-code` flow for email) is version-specific and
  must be validated against a running casdoor-all-in-one before going live.
- **AI-cloak media-proxy ships DARK** (`app.media.poisoning.enabled=false`) until
  the round-trip survival gate is verified on a real GPU cluster. The heavy-tier
  worker is optional; the lean fallback never *forces* posting to block.
- **Domain-scoping is on `feat/domain-foundation`, not yet on `main`.** A
  single-issuer cluster resolves `DOMAIN_default` and behaviour is unchanged; the
  multi-issuer decoder + per-query domain predicate are documented above as branch
  intent.
- **Owner-enforcement coverage.** Enforced in EVERY service method (owner = JWT
  subject; body userId ignored) and tested at both the service layer
  (spoofed-body, owner+id-scoped delete) and the repository/SQL layer (owner
  isolation). The federation cards path relies on **federation-api** honoring the
  forwarded JWT for its own `/mine` scoping — the BFF guarantees the correct token
  is forwarded (covered by `FederationWebClientConfigTest`); the upstream scoping
  itself is federation-api's contract, exercised here against a mock, not a live
  federation-api.
- **Native image** is best-effort hint-wise; an authoritative `-Pnative
  native:compile` on a GraalVM host is the real check (not run in this CI).
- **Paired `snapdragon-user-ui`** is built later, NOT here; this BFF's
  `/v3/api-docs` spec is the contract its ng-openapi-gen typed client will consume.
