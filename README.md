# snapdragon-user-bff-api

Spring **user BFF** — the `ROLE_USER`-floor backend paired with the (later)
`snapdragon-user-ui`. Reactive WebFlux + R2DBC + Liquibase + Casdoor JWT
resource-server + springdoc + Spring Native, scaffolded from the
`snapdragon-admin-bff-api` template (same stack, same conventions). Java 21,
Spring Boot 3.5.5.

**Owner-enforcement is the core invariant**: every endpoint operates ONLY on the
caller's OWN data. The owner is ALWAYS the Casdoor **JWT subject**
(`jwt.getSubject()`) — never a path or request-body field. A user can never
read/write another user's profile, preferences, cards, or blocks. There is
deliberately no `/profile/{userId}` style route; the only data a caller can
address is their own, identified by the token. The request body's `userId` is
ignored on writes (always overwritten with the JWT subject) so it cannot redirect
a write to another user.

## API surface (all under `/bff/user/**`, `ROLE_USER`, owner-enforced)

### Profile — `ProfileController` (`/bff/user/profile`)
Own R2DBC `user_profile` table (one row per user; `user_id` = JWT subject = PK).
Fields: `gender, pronouns, timezone, displayName, visibility {public|internal}
(default internal), vanitySubdomainEnabled`.

- `GET /bff/user/profile` — my profile (an empty default if none yet).
- `PUT /bff/user/profile` — create/update my profile (body `userId` ignored).
- `DELETE /bff/user/profile` — delete my profile.
- `POST /bff/user/profile/password` — change my **Casdoor** password.
- `POST /bff/user/profile/email` — change my **Casdoor** email.

Password + email are owned by the **Casdoor IdP**, not this BFF — they go through
a reactive `CasdoorUserClient` (the BFF never stores credentials). See deferrals.

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
- `DELETE /bff/user/blocks/{id}` — remove one of my blocks (scoped by owner AND id).
- `POST /bff/user/recommend-instance-block` — start the **USER → MOD → ADMIN**
  instance-block chain via federation `POST /api/federation/moderation`
  (`kind=instance-block`; federation sets `status=recommended` server-side). This
  is a *recommendation*, not a self-block.

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
never *forced* to block.

The server-owned opt-out: the `mode` is read **on the upload request** and persisted,
so absence of a follow-up call can never silently lose the choice — default-on is
auditable, not a UI-only convention.

## Where data lives (the routing rule)

| Concern | Destination |
| --- | --- |
| Profile fields, home-guide prefs, self-block rows | **own R2DBC tables** (`user_profile`, `user_preference`, `user_block`) |
| Password / email change | **Casdoor IdP** (`CasdoorUserClient`) — never stored here |
| Cards (federation bundles) + instance-block recommendation | **snapdragon-federation-api** (reactive `FederationApiClient`, forwarded JWT) |
| External mute/block push | **Matrix (tuwunel)** / **Mastodon (Akkoma)** clients (STUBBED) |

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

## Security — defence in depth

`SecurityConfig` is a Casdoor OAuth2 resource server (`issuer-uri` from
`CASDOOR_ISSUER_URI`). The JWT→authority converter is the **verbatim** Casdoor
converter from `snapdragon-admin-bff-api` / the gateway: `ROLE_USER` floor on every
authenticated principal; `roles` (string or `{name}`) → `ROLE_<UPPER>`;
`permissions` verbatim; `isAdmin` → `ROLE_ADMIN`. `@EnableReactiveMethodSecurity`
+ `@PreAuthorize("hasRole('USER')")` on the controllers re-checks at the method.
Profile/spec gating is profile-split: under `dev`/`test` the OpenAPI spec + Swagger
UI are public (so `gen:fetch` can curl `/v3/api-docs` tokenless); in prod they need
`ROLE_ADMIN`. Actuator health/info are public for probes.

## Stack

Reactive WebFlux everywhere (Mono/Flux, reactive WebClient; no `.block()` /
`Thread.sleep` on the event loop). R2DBC for all runtime data; JDBC only for the
Liquibase migrations (`db/changelog`). Spring Native: `native` profile +
native-maven-plugin, surefire `argLine -Dnet.bytebuddy.experimental=true`,
`NativeHintsConfig` with reflection hints for the JSON-bound DTOs +
swagger-ui webjar resource hints. `R2dbcConvertersConfig` maps Postgres/H2
timestamp types → `Instant` deterministically (JVM + native).

## Build / test

- `./mvnw test` — 48 tests, all green. Coverage: the Casdoor authorities
  converter; ROLE_USER + spec role-gating (`@WebFluxTest`); `user_profile` /
  `user_preference` / `user_block` repository slices over H2-PG-compat with the
  REAL Liquibase changelog (`TestDatabaseConfig`); **owner-enforcement**
  (`ProfileService` ignores a spoofed body userId; `BlockService` unblock is
  owner+id-scoped; repo slices assert owner isolation at the SQL layer); the
  home-guide dismiss round-trip; the federation / Casdoor / Matrix / Mastodon
  clients + the JWT-forwarding filter against a mocked `ExchangeFunction`; and a
  full-context load test.
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
- **Casdoor password/email change is STUBBED by default** (`casdoor.account.enabled
  =false`). The reactive `CasdoorUserClient` flow runs end-to-end (controller →
  service → client) and returns `casdoor: "stubbed"`; the exact Casdoor payload +
  per-user auth (caller's own session vs. a service credential, and the
  `send-verification-code`/`verify-code` flow for email) is version-specific and
  must be validated against a running casdoor-all-in-one before going live.
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
