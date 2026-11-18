package net.hugmesh.userbff.auth;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import net.hugmesh.authcore.reserved.ReservedNames;
import net.hugmesh.userbff.profile.CasdoorUserClient;
import net.hugmesh.userbff.profile.UsernameSkeleton;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

/**
 * Sign in, and invite-gated sign-up, with Google or Discord (hugmesh-generator#1107).
 * SHIPS DARK ({@code app.bff.oauth.enabled=false}).
 *
 * <ul>
 *   <li>{@code GET /bff/oauth/providers} — the providers THIS host's domain offers (the
 *       login page draws a button for each). Empty while dark.</li>
 *   <li>{@code GET /bff/oauth/{provider}/start} — seals a state cookie and redirects to the
 *       provider.</li>
 *   <li>{@code GET /bff/oauth/{provider}/callback} — the provider's redirect back.</li>
 * </ul>
 *
 * <p><b>Sign-in</b> (the SIGNIN phase): the provider code goes to Casdoor, which exchanges it
 * itself, finds the account LINKED to the provider's id, runs MFA, and returns a one-time code
 * that the SAME completion as {@code POST /bff/login} redeems (exchange, provision, custody,
 * {@code bff_} cookie). No token, code, state or Casdoor URL reaches the browser.
 *
 * <p><b>Sign-up</b> (the SIGNUP phase): Casdoor sign-up stays OFF on every application, so an
 * unlinked person is refused by Casdoor ("does not exist and is not allowed to sign up"). The
 * callback then sends the browser back to the provider once more; on that return user-bff
 * exchanges the code ITSELF to learn the provider's immutable id and a VERIFIED email, checks
 * the invite in admin-bff's allowlist (Google: the verified email; Discord: the username, the
 * key invites are written under), creates the Casdoor account linked to that id, and sends the
 * browser to the provider a last time, now to sign in. Those extra redirects happen once per
 * person (operator decision, token path (a)).
 *
 * <p>Every refusal is a redirect to {@code /login?oauth=<reason>}, never a page that names an
 * internal detail: {@code unavailable}, {@code expired}, {@code denied}, {@code mfa},
 * {@code not_invited}, {@code unverified}, {@code taken}, {@code failed}.
 */
@Tag(name = "OAuth sign-in", description =
        "Google/Discord sign-in and invite-gated sign-up through Casdoor. Ships dark behind app.bff.oauth.enabled.")
@RestController
@RequestMapping("/bff/oauth")
public class OAuthController {

    private static final Logger log = LoggerFactory.getLogger(OAuthController.class);

    /** Where a refusal lands: the login page, with a reason it can explain. */
    static final String LOGIN = "/login";
    /** Where a completed sign-in lands. */
    static final String HOME = "/";

    private final OAuthSettings settings;
    private final OAuthStateCodec codec;
    private final OAuthIdentityClient identity;
    private final CasdoorLoginClient casdoorLogin;
    private final OidcLoginCompletionService completion;
    private final AdminBffInternalClient adminBff;
    private final CasdoorUserClient casdoorUsers;
    private final String application;
    private final String redirectUri;
    private final boolean secureCookie;

    public OAuthController(OAuthSettings settings, OAuthStateCodec codec,
                           OAuthIdentityClient identity, CasdoorLoginClient casdoorLogin,
                           OidcLoginCompletionService completion, AdminBffInternalClient adminBff,
                           CasdoorUserClient casdoorUsers,
                           @Value("${app.bff.oidc.application:app-user-bff}") String application,
                           @Value("${app.bff.oidc.redirect-uri:https://hugmesh.net/login/callback}")
                           String redirectUri,
                           @Value("${app.session.cookie.secure:true}") boolean secureCookie) {
        this.settings = settings;
        this.codec = codec;
        this.identity = identity;
        this.casdoorLogin = casdoorLogin;
        this.completion = completion;
        this.adminBff = adminBff;
        this.casdoorUsers = casdoorUsers;
        this.application = application;
        this.redirectUri = redirectUri;
        this.secureCookie = secureCookie;
    }

    @Operation(summary = "The sign-in providers this host's domain offers (empty while dark).")
    @GetMapping("/providers")
    public Map<String, Object> providers(ServerWebExchange exchange) {
        List<String> ids = settings.providersFor(host(exchange)).stream()
                .map(OAuthProvider::id).toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("providers", codec.available() ? ids : List.of());
        return out;
    }

    @Operation(summary = "Start a Google/Discord sign-in: seal the state cookie, redirect to the provider.")
    @GetMapping("/{provider}/start")
    public Mono<ResponseEntity<Void>> start(@PathVariable("provider") String provider,
                                            ServerWebExchange exchange) {
        Optional<OAuthProvider> p = OAuthProvider.byId(provider);
        String host = host(exchange);
        if (p.isEmpty() || !settings.allows(host, p.get()) || !codec.available()) {
            return Mono.just(fail("unavailable", false));
        }
        return Mono.just(toProvider(p.get(), OAuthStateCodec.Phase.SIGNIN, host));
    }

    @Operation(summary = "The provider's redirect back: sign in through Casdoor, or run the invite leg.")
    @GetMapping("/{provider}/callback")
    public Mono<ResponseEntity<Void>> callback(@PathVariable("provider") String provider,
                                               @RequestParam(value = "code", required = false) String code,
                                               @RequestParam(value = "state", required = false) String state,
                                               @RequestParam(value = "error", required = false) String error,
                                               ServerWebExchange exchange) {
        String host = host(exchange);
        HttpCookie cookie = exchange.getRequest().getCookies().getFirst(OAuthStateCodec.COOKIE);
        Optional<OAuthStateCodec.State> sealed = codec.open(cookie == null ? null : cookie.getValue());
        Optional<OAuthProvider> p = OAuthProvider.byId(provider);
        // the binding: the provider's state must be the one sealed for THIS provider and host
        if (p.isEmpty() || sealed.isEmpty() || sealed.get().provider() != p.get()
                || !sealed.get().host().equals(host) || state == null
                || !state.equals(sealed.get().state())) {
            return Mono.just(fail("expired", true));
        }
        if (error != null && !error.isBlank()) {
            return Mono.just(fail("denied", true));
        }
        if (code == null || code.isBlank()) {
            return Mono.just(fail("failed", true));
        }
        if (!settings.allows(host, p.get())) {
            return Mono.just(fail("unavailable", true));
        }
        OAuthStateCodec.State s = sealed.get();
        Mono<ResponseEntity<Void>> leg = s.phase() == OAuthStateCodec.Phase.SIGNIN
                ? signIn(p.get(), code, s, host, exchange)
                : signUp(p.get(), code, host);
        return leg.onErrorResume(e -> {
            log.warn("[oauth] {} {} leg failed: {}", p.get().id(), s.phase(), e.toString());
            return Mono.just(fail("failed", true));
        });
    }

    /** SIGNIN: Casdoor exchanges the code and signs in the linked account (or refuses). */
    private Mono<ResponseEntity<Void>> signIn(OAuthProvider p, String code,
                                              OAuthStateCodec.State s, String host,
                                              ServerWebExchange exchange) {
        Pkce pkce = Pkce.generate();
        return casdoorLogin.loginWithProvider(p.casdoorProvider(), code, s.state(),
                        pkce.challenge(), redirectUri, callbackUrl(host, p))
                .flatMap(result -> switch (result.kind()) {
                    case CODE -> completion.complete(result.code(), pkce.verifier(), redirectUri,
                                    exchange)
                            .map(done -> redirect(HOME, true));
                    // The provider code is spent and Casdoor's MFA follow-up is bound to its
                    // own session, which this server-side call does not hold: send the person
                    // to the password form, which runs MFA, instead of a half-signed-in state.
                    case MFA_REQUIRED -> Mono.just(fail("mfa", true));
                    case ERROR -> Mono.just(CasdoorLoginClient.isUnknownAccount(result.message())
                            ? toProvider(p, OAuthStateCodec.Phase.SIGNUP, host)
                            : fail("failed", true));
                });
    }

    /** SIGNUP: learn who this is, check the invite, create the linked account, then sign in. */
    private Mono<ResponseEntity<Void>> signUp(OAuthProvider p, String code, String host) {
        Optional<OAuthSettings.Client> client = settings.client(p);
        if (client.isEmpty()) {
            return Mono.just(fail("unavailable", true));
        }
        return identity.identify(p, client.get(), code, callbackUrl(host, p))
                .flatMap(who -> {
                    if (who.id() == null || who.id().isBlank()) {
                        return Mono.just(fail("failed", true));
                    }
                    if (!who.hasVerifiedEmail() && p == OAuthProvider.GOOGLE) {
                        return Mono.just(fail("unverified", true));
                    }
                    String inviteKey = p == OAuthProvider.GOOGLE ? who.email() : who.username();
                    if (inviteKey == null || inviteKey.isBlank()) {
                        return Mono.just(fail("not_invited", true));
                    }
                    return adminBff.invite(p.id(), inviteKey)
                            .flatMap(inv -> inv.invited()
                                    ? account(p, who, inv, host)
                                    : Mono.just(fail("not_invited", true)));
                });
    }

    /**
     * The account an invited person signs in to. An invite that NAMES its user (provisioned
     * from the Studio's user row) is that account: created when it does not exist yet, linked
     * when it exists without a link, used as is when it is already linked to this id, and
     * refused ({@code taken}) when it is linked to someone else. An invite that names nobody
     * gets a name derived from the provider's profile; that name is only ever CREATED, never
     * linked to an account that already holds it (that would hand a stranger's account to
     * whoever has the matching provider name).
     */
    private Mono<ResponseEntity<Void>> account(OAuthProvider p, OAuthIdentityClient.Identity who,
                                               AdminBffInternalClient.Invite inv, String host) {
        boolean named = inv.username() != null && !inv.username().isBlank();
        String username = named ? inv.username() : usernameFor(p, who);
        if (username.isEmpty()) {
            return Mono.just(fail("taken", true));
        }
        String field = p.casdoorUserField();
        return casdoorUsers.linkOf(username, field)
                .flatMap(link -> {
                    if (link.isEmpty()) {
                        return casdoorUsers.addLinkedUser(username, who.username(), who.email(),
                                field, who.id()).thenReturn(true);
                    }
                    String have = link.get();
                    if (have.equals(who.id())) {
                        return Mono.just(true);
                    }
                    if (named && have.isBlank()) {
                        return casdoorUsers.linkExistingUser(username, field, who.id())
                                .thenReturn(true);
                    }
                    return Mono.just(false);
                })
                .map(ok -> ok ? toProvider(p, OAuthStateCodec.Phase.SIGNIN, host)
                        : fail("taken", true))
                .onErrorResume(e -> Mono.just(fail(
                        String.valueOf(e.getMessage()).contains("exist") ? "taken" : "failed",
                        true)));
    }

    /**
     * The Casdoor username a newly invited person gets: Discord's username, or the local part
     * of the verified Google email, folded to {@code [a-z0-9_-]}, at most 39 characters. Empty
     * when nothing usable is left or the name is reserved (the person is then told the name is
     * taken and an admin can create the account).
     */
    static String usernameFor(OAuthProvider p, OAuthIdentityClient.Identity who) {
        String base = p == OAuthProvider.DISCORD ? who.username()
                : who.email() == null ? "" : who.email().split("@", 2)[0];
        String folded = base == null ? "" : base.toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9_-]", "_").replaceAll("_+", "_")
                .replaceAll("^[_-]+|[_-]+$", "");
        if (folded.length() > 39) {
            folded = folded.substring(0, 39);
        }
        // the registry's own confusable rule (4dmin ~ admin) on top of the exact reserved
        // list; Casdoor's add-user webhook to signup-gate re-checks against existing names
        return folded.isEmpty() || ReservedNames.isReserved(folded)
                || UsernameSkeleton.isReservedConfusable(folded) ? "" : folded;
    }

    // ── the redirects ───────────────────────────────────────────────────────────────────
    private ResponseEntity<Void> toProvider(OAuthProvider p, OAuthStateCodec.Phase phase,
                                            String host) {
        OAuthSettings.Client client = settings.client(p).orElseThrow();
        OAuthStateCodec.State s = codec.issue(p, phase, application, host, settings.stateTtl());
        URI to = UriComponentsBuilder.fromUriString(client.authorize(p))
                .queryParam("response_type", "code")
                .queryParam("client_id", client.clientId())
                .queryParam("redirect_uri", callbackUrl(host, p))
                .queryParam("scope", p.scope())
                .queryParam("state", s.state())
                .encode().build().toUri();
        ResponseCookie c = ResponseCookie.from(OAuthStateCodec.COOKIE, codec.seal(s))
                .httpOnly(true).secure(secureCookie).sameSite("Lax")
                .path(OAuthStateCodec.COOKIE_PATH)
                .maxAge(settings.stateTtl()).build();
        return ResponseEntity.status(HttpStatus.FOUND).location(to)
                .header("Set-Cookie", c.toString()).build();
    }

    private ResponseEntity<Void> fail(String reason, boolean clearCookie) {
        return redirect(LOGIN + "?oauth=" + reason, clearCookie);
    }

    private ResponseEntity<Void> redirect(String to, boolean clearCookie) {
        ResponseEntity.BodyBuilder b = ResponseEntity.status(HttpStatus.FOUND).location(URI.create(to));
        if (clearCookie) {
            b.header("Set-Cookie", ResponseCookie.from(OAuthStateCodec.COOKIE, "")
                    .httpOnly(true).secure(secureCookie).sameSite("Lax")
                    .path(OAuthStateCodec.COOKIE_PATH).maxAge(0).build().toString());
        }
        return b.build();
    }

    /** The provider's redirect target on this host (registered on the provider's OAuth client). */
    static String callbackUrl(String host, OAuthProvider p) {
        return "https://" + host + "/bff/oauth/" + p.id() + "/callback";
    }

    /**
     * The request's {@code host[:port]} (the port only when it is not the scheme's default):
     * the callback URL and the state binding keep it, so a stack served on a non-default port
     * (the local compose stack's :9080) gets back to itself; the domain match drops it.
     */
    static String host(ServerWebExchange exchange) {
        URI u = exchange.getRequest().getURI();
        String h = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        int port = u.getPort();
        return port > 0 && port != 443 && port != 80 && !h.isEmpty() ? h + ":" + port : h;
    }
}
