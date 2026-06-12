package systems.snapdragon.userbff.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerReactiveAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.CasdoorAuthorities;
import systems.snapdragon.userbff.security.DomainRegistry;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CONFIG-GATED, backward-compatible multi-issuer (per-brand Casdoor) wiring. COPIED
 * (logic) from the adversarially-verified-safe snapdragon-gateway
 * {@code TenancyResourceServerConfig} (package adjusted).
 *
 * <p>Contributes a per-issuer {@link ReactiveAuthenticationManagerResolver} ONLY
 * when {@code app.tenancy.issuers} actually carries issuer=domain pairs (the
 * {@code .contains('=')} guard) — NOT merely when the property is "present" with the
 * empty {@code ${APP_TENANCY_ISSUERS:}} default, which a bare
 * {@code @ConditionalOnProperty(name=...)} would have treated as present-and-true
 * and so ALWAYS activated. {@code SecurityConfig} additionally only swaps onto this
 * resolver when {@link DomainRegistry#isMultiIssuer()} (more than the lone
 * back-compat entry), so a single-issuer cluster keeps the existing single
 * {@code o.jwt(...)} issuer-uri path verbatim and is byte-for-byte unchanged.
 *
 * <p><b>Fail-closed on unknown issuer.</b> The resolver's allowlist is exactly
 * {@link DomainRegistry#trustedIssuers()} (the configured per-brand Casdoors). A
 * token whose {@code iss} is not in that set gets NO manager and 401s before any
 * authority is emitted.
 *
 * <p><b>Custom converter preserved per issuer.</b> {@code fromTrustedIssuers}'s
 * built-in managers use the DEFAULT authorities converter and would NOT emit the
 * {@code DOMAIN_<x>} authority. So we build each per-issuer
 * {@link JwtReactiveAuthenticationManager} ourselves and set the SAME Casdoor
 * authorities converter on it — identical authority output to the single-issuer
 * path, plus the issuer-derived {@code DOMAIN_<x>}.
 */
@Configuration
// Fire ONLY when app.tenancy.issuers genuinely carries issuer=domain pairs. The
// '=' guard makes the empty ${APP_TENANCY_ISSUERS:} default a no-op: an empty
// string is "present and not false" to @ConditionalOnProperty, which would have
// activated this bean (and silently routed single-issuer clusters through the
// resolver / OIDC discovery). A valid CSV always contains at least one '='.
@ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")
public class TenancyResourceServerConfig {

    private final DomainRegistry domainRegistry;

    /** Explicit issuer-uri of the lone back-compat issuer (the single-issuer
     *  {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}). Paired with
     *  {@link #backCompatJwkSetUri} to build a discovery-free decoder for it when a
     *  jwk-set-uri is also configured. */
    private final String backCompatIssuer;

    /** Explicit jwk-set-uri of the lone back-compat issuer — used to build the
     *  per-issuer decoder WITHOUT OIDC discovery when present. Empty in the BFF's
     *  default profile (which configures only issuer-uri), in which case the
     *  back-compat issuer discovers from its iss like any other. */
    private final String backCompatJwkSetUri;

    public TenancyResourceServerConfig(
            DomainRegistry domainRegistry,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri:}") String backCompatIssuer,
            @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri:}") String backCompatJwkSetUri) {
        this.domainRegistry = domainRegistry;
        this.backCompatIssuer = trimSlash(backCompatIssuer);
        this.backCompatJwkSetUri = backCompatJwkSetUri == null ? "" : backCompatJwkSetUri.trim();
    }

    private static String trimSlash(String s) {
        if (s == null) return "";
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    @Bean
    ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantAuthManagerResolver() {
        // Cache one manager per trusted issuer (decoder construction does network
        // discovery — build lazily on first sight, never per request).
        Map<String, ReactiveAuthenticationManager> byIssuer = new ConcurrentHashMap<>();

        // Per-issuer resolver: ONLY trusted issuers (registry keys) get a manager;
        // an unknown iss yields Mono.empty() -> 401 (fail-closed).
        ReactiveAuthenticationManagerResolver<String> byIssuerResolver = issuer -> {
            if (issuer == null || !domainRegistry.isTrusted(issuer)) {
                return Mono.empty();
            }
            return Mono.just(byIssuer.computeIfAbsent(issuer, this::managerForIssuer));
        };

        JwtIssuerReactiveAuthenticationManagerResolver delegate =
                new JwtIssuerReactiveAuthenticationManagerResolver(byIssuerResolver);
        return delegate::resolve;
    }

    /** Build the per-issuer manager wired to the SAME Casdoor authorities converter
     *  the single-issuer path uses, so the {@code DOMAIN_<x>} authority is emitted in
     *  multi-issuer mode too. */
    private ReactiveAuthenticationManager managerForIssuer(String issuer) {
        JwtReactiveAuthenticationManager mgr =
                new JwtReactiveAuthenticationManager(decoderForIssuer(issuer));
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter());
        mgr.setJwtAuthenticationConverter(converter);
        return mgr;
    }

    /** Decoder for an issuer. The lone back-compat issuer (when a jwk-set-uri is also
     *  configured) gets a discovery-free {@code withJwkSetUri} decoder + the standard
     *  exp/nbf validators + an {@code iss}-binding validator. Any other (per-brand)
     *  issuer — and the back-compat issuer without a jwk-set-uri — uses
     *  {@code fromIssuerLocation} discovery (the BFF's default single-issuer profile
     *  configures only issuer-uri, so that path already discovers). */
    private ReactiveJwtDecoder decoderForIssuer(String issuer) {
        String iss = trimSlash(issuer);
        if (!backCompatJwkSetUri.isEmpty() && !backCompatIssuer.isEmpty()
                && backCompatIssuer.equals(iss)) {
            NimbusReactiveJwtDecoder decoder =
                    NimbusReactiveJwtDecoder.withJwkSetUri(backCompatJwkSetUri).build();
            OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(iss);
            decoder.setJwtValidator(withIssuer);
            return decoder;
        }
        return ReactiveJwtDecoders.fromIssuerLocation(iss);
    }

    /** The Casdoor authorities converter — identical shape to
     *  {@code SecurityConfig.casdoorAuthoritiesConverter()} (kept in sync so a token
     *  maps to the same authorities regardless of which decoder path validated it),
     *  with the issuer-derived {@code DOMAIN_<x>} added. */
    private Converter<Jwt, Flux<GrantedAuthority>> authoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry);
    }
}
