package systems.snapdragon.userbff.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Flux;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Casdoor-aware OAuth2 resource-server security for the user BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates any
 * {@code @PreAuthorize} gates on the controllers. The JWT→authority mapping is
 * COPIED VERBATIM (logic) from snapdragon-admin-bff-api / snapdragon-gateway:
 * Casdoor's {@code roles} claim (string or {name} objects), {@code permissions},
 * and {@code isAdmin} become authorities; every authenticated principal also gets
 * {@code ROLE_USER}.
 *
 * <p>This BFF's floor is {@code ROLE_USER}: the converter adds {@code ROLE_USER}
 * to every authenticated principal, so the entire {@code /bff/user/**} surface is
 * gated to "any authenticated caller" (i.e. ROLE_USER). Owner-enforcement
 * (owner = JWT subject) is applied IN the controllers/services — the security
 * layer only proves authentication, the service layer proves ownership.
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. {@code /v3/api-docs} is the raw
     * OpenAPI JSON the platform ng-openapi-gen typed clients (the paired
     * snapdragon-user-ui) + the docs pipeline fetch. Gated per profile (see the two
     * filter-chain beans): public under dev/test so {@code gen:fetch} can curl the
     * spec without a token, ROLE_ADMIN everywhere else (prod) so the API contract is
     * never publicly reachable — matching the admin-bff template.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The
     * ONLY difference between the two profiles is how {@link #SPEC_PATHS} is gated,
     * so every other route lives here to keep the two chains in lockstep and make
     * it impossible to loosen a non-spec route by editing only one chain.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // The entire user surface — ROLE_USER floor. The converter adds ROLE_USER to
        // every authenticated principal, so .authenticated() == the ROLE_USER floor.
        // No pre-auth /login or /register: this BFF is JWT-only (post-login); the
        // admin-bff owns registration. Owner-enforcement (owner = JWT subject) is in
        // the services.
        ex.pathMatchers("/bff/user/**").authenticated();
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so
     * {@code gen:fetch} (ng-openapi-gen) and the docs pipeline can curl
     * {@code /v3/api-docs} locally without a Casdoor token. Activate with
     * {@code SPRING_PROFILES_ACTIVE=dev} (or the {@code test} profile the slice
     * tests use). Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter())))
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN so the API
     * contract is never publicly reachable. Mirrors the admin-bff profile split.
     * Every non-spec route is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasRole("ADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(o -> o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter())))
                .build();
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor claim -> Spring authority mapping. Package-private + static so it can
     * be unit-tested directly against synthetic {@link Jwt}s (identical logic to
     * the admin-bff/gateway converter):
     * <ul>
     *   <li>every authenticated principal gets a {@code ROLE_USER} floor;</li>
     *   <li>each {@code roles} entry (string or {@code {name}}) becomes
     *       {@code ROLE_<UPPER>};</li>
     *   <li>each {@code permissions} entry becomes a verbatim authority;</li>
     *   <li>{@code isAdmin == true} adds {@code ROLE_ADMIN}.</li>
     * </ul>
     */
    static Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

            Object rolesClaim = jwt.getClaim("roles");
            if (rolesClaim instanceof Collection<?> list) {
                for (Object r : list) {
                    String name = roleNameOf(r);
                    if (!name.isBlank()) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + name.trim().toUpperCase()));
                    }
                }
            }

            Object permsClaim = jwt.getClaim("permissions");
            if (permsClaim instanceof Collection<?> list) {
                for (Object p : list) {
                    if (p != null) authorities.add(new SimpleGrantedAuthority(p.toString().trim()));
                }
            }

            if (Boolean.TRUE.equals(jwt.getClaim("isAdmin"))) {
                authorities.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
            }

            return Flux.fromIterable(authorities);
        };
    }

    private static String roleNameOf(Object item) {
        if (item instanceof String s) return s;
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s;
        }
        return "";
    }
}
