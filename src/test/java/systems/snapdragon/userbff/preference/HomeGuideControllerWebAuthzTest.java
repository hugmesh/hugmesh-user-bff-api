package systems.snapdragon.userbff.preference;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.commons.security.DomainRegistry;
import systems.snapdragon.userbff.security.PrincipalDomain;

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
 * HTTP-boundary authorization test for {@link HomeGuideController} — wave-2
 * controller/filter-layer coverage. This complements (does NOT duplicate) the
 * service-layer {@code HomeGuideServiceTest} (DB owner isolation) and the existing
 * per-controller {@code @PreAuthorize} role-gate slices: here we prove the
 * <b>owner == JWT subject</b> and <b>domain == validated JWT issuer</b> invariants
 * are enforced AT THE WEB LAYER, and that they are NEVER influenced by a request
 * param/body.
 *
 * <p>Critically, this slice imports the REAL {@link PrincipalDomain} +
 * {@link DomainRegistry} (configured multi-issuer via {@code @TestPropertySource})
 * rather than mocking the domain resolver, so the domain handed to the service is
 * genuinely derived from the token's {@code iss} claim — the cross-domain DENY path
 * is exercised end-to-end through the controller.
 *
 * <ul>
 *   <li>anonymous (no token) → 401 on GET/POST/PUT/DELETE; service never called;</li>
 *   <li>a principal WITHOUT {@code ROLE_USER} (only a {@code DOMAIN_*} tenant
 *       authority) → 403 (the class {@code @PreAuthorize("hasRole('USER')")});</li>
 *   <li>{@code ROLE_USER} → 200, service called with {@code owner == jwt.getSubject()};</li>
 *   <li>OWNER is the JWT subject, never a request param: even a {@code ?owner=}/
 *       {@code ?user=} query param is ignored — the subject "alice" is always passed;</li>
 *   <li>DOMAIN is the validated JWT issuer: a brand-X token → service sees
 *       {@code "brandx"}; a brand-Y token → {@code "brandy"} (cross-domain isolation);</li>
 *   <li>a non-SUPERADMIN with an UNKNOWN issuer FAILS CLOSED to the non-matchable
 *       {@code "__deny__"} sentinel — the controller's cross-domain DENY at the HTTP
 *       boundary;</li>
 *   <li>SUPERADMIN resolves the {@code null} cross-domain bypass.</li>
 * </ul>
 */
@WebFluxTest(controllers = HomeGuideController.class)
@Import({SecurityConfig.class, PrincipalDomain.class, DomainRegistry.class})
@TestPropertySource(properties = {
        // Multi-issuer registry: two trusted brands so the issuer-derived domain is
        // observable AND an unlisted issuer fails closed. (No real JWT validation runs
        // — mockJwt() bypasses the decoder; the issuer claim on the synthetic token is
        // what PrincipalDomain reads.)
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
        "app.tenancy.issuers=https://id.brandx.example=brandx,https://id.brandy.example=brandy"
})
class HomeGuideControllerWebAuthzTest {

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
    @MockitoBean HomeGuideService guides;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    @Nested
    class Unauthenticated {
        @Test
        void getStatus_anonymous_isUnauthorized_serviceNeverCalled() {
            client.get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(guides, never()).isDismissed(anyString(), anyString(), any());
        }

        @Test
        void dismiss_anonymous_isUnauthorized_serviceNeverCalled() {
            client.post().uri("/bff/user/home-guide/dismiss")
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(guides, never()).dismiss(anyString(), anyString(), any());
        }

        @Test
        void dismissPut_anonymous_isUnauthorized() {
            client.put().uri("/bff/user/home-guide/dismiss")
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(guides, never()).dismiss(anyString(), anyString(), any());
        }

        @Test
        void reset_anonymous_isUnauthorized_serviceNeverCalled() {
            client.delete().uri("/bff/user/home-guide/dismiss")
                    .exchange()
                    .expectStatus().isUnauthorized();
            verify(guides, never()).reset(anyString(), anyString(), any());
        }
    }

    @Nested
    class RoleGate {
        /**
         * A principal that is authenticated but carries ONLY a {@code DOMAIN_*} tenant
         * authority (NO {@code ROLE_USER}) is forbidden by the class-level
         * {@code @PreAuthorize("hasRole('USER')")}. This proves the method-security
         * interceptor is active for this controller (a pure path-rule slice would let
         * any authenticated caller through the {@code /bff/user/**} floor).
         */
        @Test
        void authenticatedWithoutRoleUser_isForbidden_serviceNeverCalled() {
            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("DOMAIN_brandx")))
                    .get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isForbidden();
            verify(guides, never()).isDismissed(anyString(), anyString(), any());
        }
    }

    @Nested
    class OwnerIsJwtSubject {
        @Test
        void getStatus_roleUser_callsServiceWithSubjectAsOwner() {
            when(guides.isDismissed(eq("alice"), eq("home"), eq("brandx")))
                    .thenReturn(Mono.just(false));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.guide").isEqualTo("home")
                    .jsonPath("$.dismissed").isEqualTo(false);

            verify(guides).isDismissed("alice", "home", "brandx");
        }

        /**
         * The owner is taken from {@code jwt.getSubject()}, NEVER from a request param.
         * A spoofed {@code ?owner=bob} (and {@code ?user=bob}) must be ignored — the
         * service is invoked with the JWT subject "alice", never "bob".
         */
        @Test
        void getStatus_spoofedOwnerParam_isIgnored_subjectWins() {
            when(guides.isDismissed(eq("alice"), eq("home"), eq("brandx")))
                    .thenReturn(Mono.just(true));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .get().uri(uri -> uri.path("/bff/user/home-guide")
                            .queryParam("owner", "bob")
                            .queryParam("user", "bob")
                            .build())
                    .exchange()
                    .expectStatus().isOk();

            verify(guides).isDismissed("alice", "home", "brandx");
            verify(guides, never()).isDismissed(eq("bob"), anyString(), any());
        }

        @Test
        void dismiss_roleUser_callsServiceWithSubjectAndIssuerDomain() {
            when(guides.dismiss(eq("alice"), eq("home"), eq("brandx")))
                    .thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .post().uri("/bff/user/home-guide/dismiss")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.dismissed").isEqualTo(true);

            verify(guides).dismiss("alice", "home", "brandx");
        }

        @Test
        void reset_roleUser_callsServiceWithSubjectAndIssuerDomain() {
            when(guides.reset(eq("alice"), eq("home"), eq("brandx")))
                    .thenReturn(Mono.empty());

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .delete().uri("/bff/user/home-guide/dismiss")
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.dismissed").isEqualTo(false);

            verify(guides).reset("alice", "home", "brandx");
        }

        @Test
        void namedGuide_isThreadedThrough_perGuideKeying() {
            when(guides.isDismissed(eq("alice"), eq("settings"), eq("brandx")))
                    .thenReturn(Mono.just(true));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("alice").issuer(BRANDX))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                    .get().uri(uri -> uri.path("/bff/user/home-guide")
                            .queryParam("guide", "settings").build())
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.guide").isEqualTo("settings")
                    .jsonPath("$.dismissed").isEqualTo(true);

            verify(guides).isDismissed("alice", "settings", "brandx");
        }
    }

    @Nested
    class DomainFromValidatedIssuer {
        /**
         * A brand-Y token resolves to {@code "brandy"} — proving the domain is keyed
         * on the (validated) {@code iss}, not a fixed value. Together with the brand-X
         * cases above this is the cross-domain isolation proof at the HTTP boundary: a
         * brand-Y caller can never reach brand-X rows because the service is invoked
         * with {@code "brandy"}, never {@code "brandx"}.
         */
        @Test
        void brandYToken_resolvesBrandY_neverBrandX() {
            when(guides.isDismissed(eq("carol"), eq("home"), eq("brandy")))
                    .thenReturn(Mono.just(false));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("carol").issuer(BRANDY))
                            .authorities(authorities("ROLE_USER", "DOMAIN_brandy")))
                    .get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isOk();

            verify(guides).isDismissed("carol", "home", "brandy");
            verify(guides, never()).isDismissed(anyString(), anyString(), eq("brandx"));
        }

        /**
         * CROSS-DOMAIN DENY at the controller: a non-SUPERADMIN whose issuer is NOT in
         * the trusted registry FAILS CLOSED — the controller hands the service the
         * non-matchable {@code "__deny__"} sentinel (never the {@code null} bypass and
         * never a forged domain), so the query can match no row. The domain is provably
         * derived from the issuer, not from a forgeable claim.
         */
        @Test
        void unknownIssuer_nonSuperadmin_failsClosedToDenySentinel() {
            when(guides.isDismissed(eq("mallory"), eq("home"), eq("__deny__")))
                    .thenReturn(Mono.just(false));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("mallory").issuer("https://evil.attacker.example"))
                            .authorities(authorities("ROLE_USER")))
                    .get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isOk();

            // never the null bypass, never a real brand — the deny sentinel.
            verify(guides).isDismissed("mallory", "home", "__deny__");
            verify(guides, never()).isDismissed(eq("mallory"), anyString(), eq("brandx"));
            verify(guides, never()).isDismissed(eq("mallory"), anyString(), eq("brandy"));
        }

        /**
         * SUPERADMIN is the cross-domain infra super-role — it resolves the {@code null}
         * bypass (no domain predicate). Proven through the controller: the service is
         * invoked with a {@code null} domain.
         */
        @Test
        void superadmin_resolvesNullCrossDomainBypass() {
            when(guides.isDismissed(eq("root"), eq("home"), eq(null)))
                    .thenReturn(Mono.just(false));

            client.mutateWith(mockJwt()
                            .jwt(j -> j.subject("root").issuer(BRANDX)
                                    .claim("roles", List.of("superadmin")))
                            .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                    .get().uri("/bff/user/home-guide")
                    .exchange()
                    .expectStatus().isOk();

            verify(guides).isDismissed("root", "home", null);
        }
    }
}
