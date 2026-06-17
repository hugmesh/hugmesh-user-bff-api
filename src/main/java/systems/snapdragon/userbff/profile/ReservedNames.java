package systems.snapdragon.userbff.profile;

import java.util.Set;

/**
 * THE CANONICAL RESERVED USERNAME / DNS-LABEL LIST (case-insensitive).
 *
 * <p>A vanity username (the FIRST DNS label of {@code <user>.snapdragon.systems}
 * or {@code <user>.snapdragon.games}) must NOT equal any of these, because each
 * one is — or could collide with — a dedicated app path-prefix route or a platform
 * service subdomain. Enabling a vanity subdomain / making a profile public with a
 * reserved username is rejected (400) in the service layer AND backed by a DB
 * CHECK on {@code user_profile.vanity_username}.
 *
 * <h2>CANONICAL SOURCE — the gateway routes (auditable)</h2>
 * This set is the UNION of the deployed route prefixes / reserved subdomains:
 * <ul>
 *   <li><b>fe-gateway</b> route prefixes (snapdragon-fe-gateway/application-fe.yml +
 *       the snapdragon.systems host nginx /_remotes): {@code admin, apidocs, be, bff,
 *       _fragments, login, mod, user};</li>
 *   <li><b>be-gateway</b> route prefixes (snapdragon-be-gateway/application-be.yml):
 *       {@code api, _matrix, oauth};</li>
 *   <li><b>reserved subdomains</b> (snapdragon.systems): {@code id, api, matrix,
 *       mastodon, pleroma, forum, wiki, owncast, tube, scale, headscale, www} —
 *       {@code forum} is the phpBB forum; {@code wiki} is the Kiwix wiki;
 *       {@code owncast} and {@code tube} are optional GPU-gated video services
 *       (all reserved so vanity subdomains can never collide);</li>
 *   <li><b>snapdragon.GAMES app route prefixes</b> — DERIVED from
 *       snapdragon.games/frontend/nginx.conf {@code /_remotes/<slug>/} blocks +
 *       location prefixes + the {@code <service>.snapdragon.games} subdomains
 *       (compose.prod.yml): the remote slugs {@code admin, api-docs, banned,
 *       games-dodecahedron, games-rpg-maker, games-three-wizards, games-vn-maker,
 *       login, mod, producer-registration, publisher, registration, wasm-fragment},
 *       the path prefixes {@code api, docs, _remotes}, and the games-flavoured
 *       front-door labels {@code games, play, wasm, producer};</li>
 *   <li><b>defensive web reserved names</b> (never a username, regardless of route):
 *       {@code root, static, assets, public, health, healthz, actuator, metrics,
 *       well-known, favicon, robots, sitemap, status, support, help, social, auth,
 *       logout, oauth2, fragments, users, gm, pki, vault, argocd, gitlab,
 *       registry}.</li>
 * </ul>
 *
 * <p><b>SHARED SOURCE.</b> This exact list text is mirrored verbatim in
 * snapdragon-federation-api ({@code systems.snapdragon.federation.controller.ReservedNames})
 * so the USER profile validation/DB layer (this repo) and the SERVING layer (the
 * federation API + its 016 reserved-slug CHECK) agree on a single vocabulary. Keep
 * the two copies identical; the canonical source of truth is the gateway route
 * config referenced above. The DB-level {@code user_profile.vanity_username} CHECK
 * (changeset 004) is generated from this same set.
 */
public final class ReservedNames {

    private ReservedNames() {}

    /**
     * Reserved first DNS labels / usernames. Lower-case; callers MUST lower-case the
     * candidate before {@link Set#contains}.
     */
    public static final Set<String> RESERVED_LABELS = Set.of(
            // --- fe-gateway route prefixes (snapdragon.systems front door) ---
            "admin", "apidocs", "be", "bff", "_fragments", "login", "mod", "user",
            // superadmin: the TAILNET superadmin App-Store console is served at
            // /superadmin/appstore/** on the superadmin-gateway — a dedicated
            // first-segment route prefix (canonical reserved-prefixes.yaml).
            "superadmin",
            // --- be-gateway route prefixes / publicly-routable homeserver surfaces ---
            // _synapse + media: PUBLICLY-ROUTABLE homeserver client surfaces the
            // route-access seed deploys — /_synapse/** (Matrix Synapse-compat,
            // matrix-host-scoped) and /media/** (Mastodon media). Real first-segment
            // route prefixes, so a vanity username equal to either would shadow them.
            "api", "_matrix", "_synapse", "media", "oauth",
            // --- reserved subdomains (snapdragon.systems) ---
            // forum/phpbb: the phpBB community forum surfaces; owncast/wiki/tube:
            // optional video/wiki/streaming services — all reserved so a vanity
            // subdomain can never collide (canonical reserved-prefixes.yaml).
            "id", "matrix", "mastodon", "pleroma", "forum", "phpbb", "wiki",
            "owncast", "tube", "scale", "headscale", "www",
            // --- snapdragon.GAMES app route prefixes (derived: nginx /_remotes/<slug>/
            //     + location prefixes + <service>.snapdragon.games subdomains) ---
            "games", "play", "wasm", "producer", "publisher", "banned",
            "api-docs", "docs", "_remotes", "producer-registration", "registration",
            "wasm-fragment", "games-dodecahedron", "games-rpg-maker",
            "games-three-wizards", "games-vn-maker", "games-instances-console",
            // --- defensive web reserved names ---
            "root", "static", "assets", "public", "health", "healthz", "actuator",
            "metrics", "well-known", "favicon", "robots", "sitemap", "status",
            "support", "help", "social", "auth", "logout", "oauth2", "fragments",
            "users", "gm", "pki", "vault", "argocd", "gitlab", "registry");

    /** Whether a candidate first-label / username is reserved (case-insensitive). */
    public static boolean isReserved(String label) {
        return label != null && RESERVED_LABELS.contains(label.trim().toLowerCase());
    }
}
