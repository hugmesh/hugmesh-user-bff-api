package systems.snapdragon.userbff.auth;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import systems.snapdragon.authcore.casdoor.BffCustodyCipher;
import systems.snapdragon.authcore.casdoor.OidcExchangeConfig;
import systems.snapdragon.authcore.config.SessionCookieService;

/**
 * Pulls the auth-core SSO building blocks this BFF's OIDC-login relocation consumes
 * into the context. They live under {@code systems.snapdragon.authcore.*} — OUTSIDE the
 * {@code systems.snapdragon.userbff} component-scan — so they are {@code @Import}ed
 * here rather than picked up by the scan (the same pattern {@code CommonsSecurityConfig}
 * uses for the commons beans):
 *
 * <ul>
 *   <li>{@link OidcExchangeConfig} — its {@code @Bean oidcExchangeClient} is gated
 *       {@code @ConditionalOnProperty(app.bff.oidc.enabled=true)}, so with the surface
 *       dark (the default) the {@code OidcExchangeClient} bean is ABSENT and
 *       {@code OidcLoginCompletionService}'s {@code ObjectProvider<OidcExchangeClient>}
 *       resolves null ⇒ fail-closed (there is no separate callback controller any more —
 *       native {@code POST /bff/login} is the sole entry, see {@code SsoAuthController});</li>
 *   <li>{@link BffCustodyCipher} — AES-256-GCM cipher for the at-rest token blobs; it
 *       self-binds {@code app.bff.custody-key} and is INERT ({@code isAvailable()==false})
 *       + fail-closed when the key is blank;</li>
 *   <li>{@link SessionCookieService} — mints/expires the opaque {@code bff_} cookie; it
 *       self-binds {@code app.session.cookie.*}. It now defaults to
 *       {@code app.session.cookie.enabled=true}, so a Set-Cookie IS emitted on
 *       {@code /bff/login}/{@code /bff/register}; the session token also stays in the
 *       response body (vestigial) so non-UI consumers are unaffected. Set the flag false
 *       to go body-only.</li>
 * </ul>
 *
 * <p>{@code OidcExchangeConfig} and {@code BffCustodyCipher} still self-default to the
 * dark/inert posture (the OIDC-exchange surface stays off until its flag/key are set);
 * only the {@code bff_} session cookie now ships live.
 */
@Configuration(proxyBeanMethods = false)
@Import({OidcExchangeConfig.class, BffCustodyCipher.class, SessionCookieService.class})
public class AuthCoreImport {
}
