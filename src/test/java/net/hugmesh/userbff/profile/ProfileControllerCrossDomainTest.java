package net.hugmesh.userbff.profile;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Cross-domain DENY + owner==subject HTTP-boundary test for {@link ProfileController},
 * using the REAL {@link PrincipalDomain} + {@link DomainRegistry} (multi-issuer) so the
 * domain handed to {@link ProfileService} is genuinely derived from the token's
 * validated {@code iss} claim — NOT a request param/body.
 *
 * <p>This is the cross-domain complement to the existing {@code ProfileControllerTest}
 * (which mocks {@code PrincipalDomain} and therefore never exercises the
 * issuer→domain derivation). Here we additionally prove the body's spoofed
 * {@code userId} influences neither the owner NOR the scoped domain:
 *
 * <ul>
 *   <li>anonymous (no token) → 401 on every method, the service never invoked;
 *       authenticated WITHOUT {@code ROLE_USER} → 403, the service never invoked
 *       (the {@code @PreAuthorize("hasRole('USER')")} + the SecurityConfig
 *       {@code /bff/user/**} floor);</li>
 *   <li>brand-X token → {@code get/save/delete} all scoped to {@code "brandx"};
 *       brand-Y token → {@code "brandy"} (a brand-Y caller is never given a brand-X
 *       scope);</li>
 *   <li>a body carrying a foreign {@code userId} ("bob") with a brand-X token still
 *       scopes to owner "alice" / domain "brandx" — the body is fully ignored for
 *       both owner and domain;</li>
 *   <li>UNKNOWN issuer (non-SUPERADMIN) → fails closed to {@code "__deny__"} for
 *       GET and DELETE (cross-domain DENY through the controller);</li>
 *   <li>SUPERADMIN → {@code null} cross-domain bypass.</li>
 * </ul>
 *
 * <p>WAVE-2C SELF-COMPLETENESS: the {@code AuthzGate} nested class adds the
 * 401-anonymous and 403-wrong-role assertions that this file previously leaned on the
 * sibling {@code ProfileControllerTest} for — every DENY is now proved IN THIS FILE,
 * through the SAME prod {@code SecurityConfig} chain that the cross-domain tests use,
 * and every DENY is mutation-resistant (paired with {@code verify(profiles, never())}
 * so removing the guard turns the test red rather than letting an unauthorized call
 * silently reach the service).
 */
@WebFluxTest(controllers = ProfileController.class)
@Import({SecurityConfig.class, PrincipalDomain.class, DomainRegistry.class})
@TestPropertySource(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
        "app.tenancy.issuers=https://id.brandx.example=brandx,https://id.brandy.example=brandy"
})
class ProfileControllerCrossDomainTest {

    private static final String BRANDX = "https://id.brandx.example";
    private static final String BRANDY = "https://id.brandy.example";

    @Autowired ApplicationContext context;
    WebTestClient client;

    // Spring Security 7: the mockJwt()/mock* reactive mutators only inject the
    // SecurityContext when the springSecurity() configurer's MutatorFilter is in the
    // chain. A @WebFluxTest-autowired client lacks it (mutator dropped -> 401), so build
    // the client from the ApplicationContext with .apply(springSecurity()).
    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ProfileService profiles;
    @MockitoBean AvatarService avatars;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static UserProfile stubProfile(String userId) {
        return new UserProfile(userId, null, null, null, "Display", "internal", false, null, null);
    }

    /**
     * SELF-COMPLETE authz gate (wave-2c): the 401-anonymous and 403-wrong-role DENYs
     * for {@link ProfileController}, asserted IN THIS FILE through the prod
     * {@link SecurityConfig} chain (this file previously relied on the sibling
     * {@code ProfileControllerTest} for the anonymous 401 and had NO wrong-role 403).
     *
     * <p>Each DENY is mutation-resistant: paired with {@code verify(profiles, never())}
     * across every {@link ProfileService} entry point, so deleting the path floor /
     * {@code @PreAuthorize} would let the call reach the (still-mocked) service and the
     * {@code never()} verify would FAIL — not silently pass on a re-derived status.
     */
    @Nested
    class AuthzGate {

        /** No token at all → 401 on GET/PUT/DELETE; the service is never invoked. */
        @Test
        void anonymous_everyMethod_isUnauthorized_serviceNeverInvoked() {
            client.get().uri("/bff/user/profile")
                    .exchange().expectStatus().isUnauthorized();
            client.delete().uri("/bff/user/profile")
                    .exchange().expectStatus().isUnauthorized();
            client.put().uri("/bff/user/profile")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(stubProfile("alice"))
                    .exchange().expectStatus().isUnauthorized();

            verify(profiles, never()).get(anyString(), any());
            verify(profiles, never()).save(anyString(), anyString(), any(), any());
            verify(profiles, never()).delete(anyString(), any());
        }

        /**
         * A genuine brand-X token that carries a domain authority but NOT
         * {@code ROLE_USER} is rejected 403 at the {@code /bff/user/**} floor +
         * {@code @PreAuthorize("hasRole('USER')")} — authenticated is not authorized.
         * The service is never invoked for any of the three owner-scoped methods (so
         * this DENY would fail-RED if the USER gate were removed).
         */
        @Test
        void authenticatedWithoutRoleUser_everyMethod_isForbidden_serviceNeverInvoked() {
            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("DOMAIN_brandx")))   // no ROLE_USER
                    .get().uri("/bff/user/profile")
                    .exchange().expectStatus().isForbidden();

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("DOMAIN_brandx")))
                    .method(HttpMethod.DELETE).uri("/bff/user/profile")
                    .exchange().expectStatus().isForbidden();

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").claim("preferred_username", "alice").issuer(BRANDX))
                            .authorities(authorities("DOMAIN_brandx")))
                    .put().uri("/bff/user/profile")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(stubProfile("alice"))
                    .exchange().expectStatus().isForbidden();

            verify(profiles, never()).get(anyString(), any());
            verify(profiles, never()).save(anyString(), anyString(), any(), any());
            verify(profiles, never()).delete(anyString(), any());
        }
    }

    @Nested
    class DomainFromValidatedIssuer {
        @Test
        void getProfile_brandX_scopedToBrandX() {
            when(profiles.get(eq("alice"), eq("brandx"))).thenReturn(Mono.just(stubProfile("alice")));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .get().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody().jsonPath("$.userId").isEqualTo("alice");

            verify(profiles).get("alice", "brandx");
            verify(profiles, never()).get(anyString(), eq("brandy"));
        }

        @Test
        void getProfile_brandY_scopedToBrandY_neverBrandX() {
            when(profiles.get(eq("carol"), eq("brandy"))).thenReturn(Mono.just(stubProfile("carol")));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("carol").issuer(BRANDY))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandy")))
                    .get().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isOk();

            verify(profiles).get("carol", "brandy");
            verify(profiles, never()).get(anyString(), eq("brandx"));
        }

        @Test
        void deleteProfile_brandX_scopedToBrandX() {
            when(profiles.delete(eq("alice"), eq("brandx"))).thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .delete().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isNoContent();

            verify(profiles).delete("alice", "brandx");
        }
    }

    @Nested
    class OwnerAndDomainNeverFromBody {
        /**
         * The spoofed body {@code userId="bob"} influences NEITHER the owner NOR the
         * domain: with a brand-X "alice" token the save is scoped to owner "alice" /
         * domain "brandx", and the username is derived from {@code preferred_username},
         * never from the body. A core BOLA + cross-tenant guard at the HTTP boundary.
         */
        @Test
        void upsert_spoofedBodyUserId_ignoredForOwnerAndDomain() {
            when(profiles.save(eq("alice"), eq("alice"), any(), eq("brandx")))
                    .thenReturn(Mono.just(stubProfile("alice")));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").claim("preferred_username", "alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .put().uri("/bff/user/profile")
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(stubProfile("bob"))     // spoofed userId
                    .exchange()
                    .expectStatus().isOk();

            verify(profiles).save(eq("alice"), eq("alice"), any(), eq("brandx"));
            verify(profiles, never()).save(eq("bob"), anyString(), any(), any());
            verify(profiles, never()).save(anyString(), anyString(), any(), eq("brandy"));
        }
    }

    @Nested
    class CrossDomainDeny {
        /** UNKNOWN issuer (non-SUPERADMIN) fails closed to the non-matchable sentinel. */
        @Test
        void getProfile_unknownIssuer_failsClosedToDenySentinel() {
            when(profiles.get(eq("mallory"), eq("__deny__"))).thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("mallory").issuer("https://evil.attacker.example"))
                            .authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isOk();   // empty body; the point is the deny-scoped query

            verify(profiles).get("mallory", "__deny__");
            verify(profiles, never()).get(eq("mallory"), eq("brandx"));
            verify(profiles, never()).get(eq("mallory"), eq("brandy"));
        }

        @Test
        void deleteProfile_unknownIssuer_failsClosedToDenySentinel() {
            when(profiles.delete(eq("mallory"), eq("__deny__"))).thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("mallory").issuer("https://evil.attacker.example"))
                            .authorities(authorities("ROLE_USER")))
                    .delete().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isNoContent();

            verify(profiles).delete("mallory", "__deny__");
        }

        /** SUPERADMIN reaches the cross-domain {@code null} bypass through the controller. */
        @Test
        void getProfile_superadmin_nullCrossDomainBypass() {
            when(profiles.get(eq("root"), eq(null))).thenReturn(Mono.just(stubProfile("root")));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("root").issuer(BRANDX).claim("roles", List.of("superadmin")))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                    .get().uri("/bff/user/profile")
                    .exchange()
                    .expectStatus().isOk();

            verify(profiles).get("root", null);
        }
    }
}
