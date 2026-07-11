package systems.snapdragon.userbff.hsproxy;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.auth.AdminBffInternalClient;

import java.util.Locale;

/**
 * D6 Matrix BFF-proxy: forwards {@code /bff/user/matrix/**} to the {@code tuwunel-proxy
 * :4443} mTLS sidecar with the caller's homeserver-NATIVE token injected (the inbound
 * Casdoor bearer is stripped). Owner is resolved from the VALIDATED JWT subject — NEVER
 * a body/path field — so a caller can only ever use THEIR OWN custody token (the
 * cross-user isolation keystone is the owner-scoped custody load).
 *
 * <p>{@code @PreAuthorize hasRole('MATRIX')} mirrors today's provision gate, on top of
 * the {@code ROLE_USER} security floor. Streaming/long-poll
 * ({@code /_matrix/client/v3/sync}) passes through verbatim via {@link HsReverseProxy}.
 *
 * <p>LIVE BY DEFAULT ({@code app.hs-token.enabled} now defaults true): this proxy is the
 * ONLY homeserver path now that the browser holds no Matrix access token. Every method
 * still 503s when {@code app.hs-token.enabled=false} OR the custody cipher key is unset
 * (fail-closed) — there is no browser-token fallback.
 */
@Tag(name = "Matrix proxy (D6)", description = "Owner-scoped Matrix reverse-proxy; injects the server-held homeserver-native token. Live by default behind app.hs-token.enabled.")
@RestController
@RequestMapping("/bff/user/matrix")
@PreAuthorize("hasRole('MATRIX')")
public class MatrixProxyController {

    private static final String PREFIX = "/bff/user/matrix";

    private final boolean enabled;
    private final HsTokenCustody custody;
    private final ServiceTokenBroker broker;
    private final HsReverseProxy proxy;
    private final AdminBffInternalClient adminBff;

    public MatrixProxyController(
            @Value("${app.hs-token.enabled:false}") boolean enabled,
            HsTokenCustody custody,
            ServiceTokenBroker broker,
            @Qualifier("matrixProxyWebClient") WebClient matrixProxyWebClient,
            AdminBffInternalClient adminBff) {
        this.enabled = enabled;
        this.custody = custody;
        this.broker = broker;
        this.proxy = new HsReverseProxy(matrixProxyWebClient);
        this.adminBff = adminBff;
    }

    @Operation(summary = "Reverse-proxy any Matrix client-API call with the server-held native token (owner = JWT subject). 503 when the feature is dark.")
    @RequestMapping("/**")
    public Mono<Void> proxy(@AuthenticationPrincipal Jwt jwt, ServerWebExchange exchange) {
        if (!enabled || !custody.cipherAvailable()) {
            // Fail-closed: feature off (or no custody key) → 503. There is NO
            // browser-token fallback — the browser holds no homeserver token.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "Matrix BFF-proxy is not enabled (app.hs-token.enabled=false)"));
        }
        String owner = jwt.getSubject();
        String upstreamPath = upstreamPath(exchange);

        Mono<String> load = custody.loadAccessToken(owner, HsServiceTokenRow.PLATFORM_MATRIX);
        // localpart(jwt) is a Mono (may hop to admin-bff over the internal surface) —
        // composed INTO the lazy remint chain rather than resolved eagerly, so the
        // account-takeover-by-collision lookup only ever fires when a mint is actually
        // needed (first-use / 401-retry — see HsReverseProxy#forward), exactly matching
        // this Mono's existing on-demand-only subscription semantics.
        Mono<String> remint = localpart(jwt).flatMap(lp -> broker.mintMatrix(owner, lp))
                .map(MintedToken::accessToken);
        return proxy.forward(exchange, upstreamPath, load, remint);
    }

    /** The homeserver-native path = the request path with the {@code /bff/user/matrix}
     *  prefix removed (so {@code /bff/user/matrix/_matrix/client/v3/sync} →
     *  {@code /_matrix/client/v3/sync}). */
    private static String upstreamPath(ServerWebExchange exchange) {
        String path = exchange.getRequest().getPath().value();
        String rest = path.length() > PREFIX.length() ? path.substring(PREFIX.length()) : "/";
        return rest.isEmpty() ? "/" : rest;
    }

    /**
     * The caller's homeserver localpart — used only for the re-mint leg, never from a
     * request field.
     *
     * <p>Account-takeover-by-collision fix, gap-1 close. Prefers the {@code localpart}
     * claim {@code BffSessionAuthenticationWebFilter} threads onto the synthetic Jwt from
     * admin-bff's PERSISTED, collision-checked {@code account.localpart} (native-login /
     * {@code bff_}-session callers — the primary path).
     *
     * <p>THE FALLBACK IS REACHABLE: a real, externally-issued, validly-signed Casdoor JWT
     * presented directly to this route never passes through
     * {@code BffSessionAuthenticationWebFilter} (that filter only ever resolves an opaque
     * {@code bff_} bearer) and so never carries the synthetic {@code localpart} claim —
     * but {@code SecurityConfig} still fully wires {@code o.jwt(...)} against the live
     * issuer-uri for this exact {@code @PreAuthorize hasRole('MATRIX')} route, so such a
     * token DOES reach this method with {@code canonical == null}. The OLD behaviour here
     * (re-deriving {@code preferred_username}/{@code sub} independently) is exactly the
     * unchecked-candidate bug this whole fix exists to close: two different accounts can
     * derive the SAME candidate, and whichever is minted second silently hijacks the
     * first's already-registered homeserver identity.
     *
     * <p>So the fallback branch resolves the SAME canonical, persisted, collision-checked
     * value the primary path reads — via a REAL internal call to admin-bff — using the
     * SAME (provider, handle) → account-id derivation admin-bff's own production mint
     * site ({@code AuthController#accountFromJwt}) and this repo's own
     * {@code SessionsService#accountIdFromJwt} already use for a genuine Casdoor JWT:
     * {@code email} claim → {@code google:<email-lc>}, else {@code preferred_username} →
     * {@code discord:<username-lc>}. FAIL CLOSED throughout (never falls back to the old
     * derivation): neither claim present, neither derived account exists, admin-bff is
     * unreachable/disabled, or the resolved account carries no persisted localpart yet →
     * the Mono errors and the mint is refused. Falling back silently here would just
     * reintroduce the exact vulnerability this fix closes.
     */
    private Mono<String> localpart(Jwt jwt) {
        String canonical = jwt.getClaimAsString("localpart");
        if (canonical != null && !canonical.isBlank()) {
            return Mono.just(canonical);
        }
        return resolveCanonicalLocalpart(jwt);
    }

    /**
     * Resolve the canonical, persisted, collision-checked localpart for a REAL Casdoor JWT
     * that carries no synthetic-session {@code localpart} claim. See {@link #localpart}'s
     * doc for the full rationale — byte-for-byte identical to
     * {@code MastodonProxyController}'s copy (this org's established duplication pattern
     * for the two D6 proxy controllers, e.g. {@code upstreamPath}/{@code PREFIX} above).
     */
    private Mono<String> resolveCanonicalLocalpart(Jwt jwt) {
        String email = jwt.getClaimAsString("email");
        String pu = jwt.getClaimAsString("preferred_username");
        Mono<AdminBffInternalClient.AccountView> byEmail = (email != null && !email.isBlank())
                ? adminBff.getAccount(idFor("google", email))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        Mono<AdminBffInternalClient.AccountView> byUsername = (pu != null && !pu.isBlank())
                ? adminBff.getAccount(idFor("discord", pu))
                        .onErrorResume(WebClientResponseException.NotFound.class, e -> Mono.empty())
                : Mono.empty();
        return byEmail.switchIfEmpty(byUsername)
                .switchIfEmpty(Mono.error(new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                        "no registered account for this token's identity claims "
                                + "(fail-closed homeserver-localpart resolution)")))
                .flatMap(a -> {
                    String lp = a.localpart();
                    return (lp == null || lp.isBlank())
                            ? Mono.error(new ResponseStatusException(HttpStatus.CONFLICT,
                                    "account has no persisted homeserver localpart yet "
                                            + "(fail-closed — will not re-derive an unchecked candidate)"))
                            : Mono.just(lp);
                });
    }

    /** Mirrors {@code AccountStore.idFor(provider, handle) = provider + ":" +
     *  handle.toLowerCase()} — the SAME textual convention {@code SessionsService
     *  .accountIdFromJwt} already documents+replicates in this repo rather than taking a
     *  compile dependency on the exact auth-core method for what is a stable, one-line
     *  identity-string format. */
    private static String idFor(String provider, String handle) {
        return provider + ":" + handle.toLowerCase(Locale.ROOT);
    }
}
