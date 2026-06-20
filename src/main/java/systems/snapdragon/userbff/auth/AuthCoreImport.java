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
 *       dark (the default) the {@code OidcExchangeClient} bean is ABSENT and the
 *       callback controller's {@code @Nullable} injection is null ⇒ fail-closed;</li>
 *   <li>{@link BffCustodyCipher} — AES-256-GCM cipher for the at-rest token blobs; it
 *       self-binds {@code app.bff.custody-key} and is INERT ({@code isAvailable()==false})
 *       + fail-closed when the key is blank;</li>
 *   <li>{@link SessionCookieService} — mints/expires the opaque {@code bff_} cookie; it
 *       self-binds {@code app.session.cookie.*} and emits NO Set-Cookie when
 *       {@code app.session.cookie.enabled=false} (the default), so the token-in-body
 *       path is byte-identical to today.</li>
 * </ul>
 *
 * <p>All three self-default to the dark/inert posture, so importing them changes
 * NOTHING at runtime until the corresponding flag is flipped on.
 */
@Configuration(proxyBeanMethods = false)
@Import({OidcExchangeConfig.class, BffCustodyCipher.class, SessionCookieService.class})
public class AuthCoreImport {
}
