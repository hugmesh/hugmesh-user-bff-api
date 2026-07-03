package systems.snapdragon.userbff.auth;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Casdoor OIDC browser-PKCE callback — the login leg owned by user-bff (so the browser
 * only ever holds the opaque {@code bff_} session, never a JWT). login-ui owns
 * client-side PKCE: it stores {@code state} + {@code verifier} in sessionStorage,
 * redirects to Casdoor, intercepts the redirect at {@code /login/callback}, validates
 * {@code state} from sessionStorage, then POSTs {@code {code, codeVerifier, redirectUri}}
 * as JSON to {@code POST /bff/auth/callback} here.
 *
 * <p>The exchange→provision→custody→cookie work is DELEGATED to the shared
 * {@link OidcLoginCompletionService} — the SAME service the native {@code POST /bff/login}
 * ({@link SsoAuthController}) uses, so the security-critical crypto/session logic is written
 * exactly once. This controller only adapts the browser-PKCE request shape (it receives the
 * verifier directly in the POST body) onto that shared completion.
 *
 * <p>SHIPS DARK: when {@code app.bff.oidc.enabled=false} (the default) auth-core's
 * {@code OidcExchangeConfig} contributes NO {@code OidcExchangeClient} bean, so the
 * completion service 503s every callback — no exchange, no internal call, no cookie. The
 * OIDC token values are NEVER put in the response body or logged; only the opaque
 * {@code bff_} session crosses back to the browser.
 *
 * @see OidcLoginCompletionService
 */
@Tag(name = "OIDC login callback", description =
        "Casdoor OIDC browser-PKCE callback. Ships dark behind app.bff.oidc.enabled; 503 when disabled.")
@RestController
@RequestMapping("/bff/auth")
public class OidcCallbackController {

    /** POST body from the login-ui's browser-side PKCE callback handoff. */
    public record OidcCallbackRequest(String code, String codeVerifier, String redirectUri) {}

    /** The non-secret routing hints the callback-completing browser needs. NEVER a JWT or token. */
    public record CallbackResult(boolean registrationComplete, String status) {}

    private final OidcLoginCompletionService completion;
    private final String defaultRedirectUri;

    public OidcCallbackController(OidcLoginCompletionService completion,
                                  @Value("${app.bff.oidc.redirect-uri:https://snapdragon.systems/login/callback}")
                                  String defaultRedirectUri) {
        this.completion = completion;
        this.defaultRedirectUri = defaultRedirectUri;
    }

    @Operation(summary = "Casdoor OIDC callback: browser-PKCE handoff. Exchange code, "
            + "provision account+session via admin-bff, set the bff_ cookie. 200+body on success. "
            + "503 when the OIDC surface is dark.")
    @PostMapping("/callback")
    public Mono<ResponseEntity<CallbackResult>> callback(@RequestBody OidcCallbackRequest body,
                                                         ServerWebExchange exchange) {
        String redirectUri = (body.redirectUri() == null || body.redirectUri().isBlank())
                ? defaultRedirectUri : body.redirectUri();
        return completion.complete(body.code(), body.codeVerifier(), redirectUri, exchange)
                .map(c -> ResponseEntity.ok(new CallbackResult(c.registrationComplete(), c.status())));
    }
}
