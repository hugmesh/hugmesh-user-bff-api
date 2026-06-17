package systems.snapdragon.userbff.profile;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;
import systems.snapdragon.userbff.security.DomainRegistry;
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

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ProfileService profiles;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    private static UserProfile stubProfile(String userId) {
        return new UserProfile(userId, null, null, null, "Display", "internal", false, null, null);
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
