package systems.snapdragon.userbff.prefstore;

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
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * Cross-domain DENY + owner==subject HTTP-boundary test for
 * {@link UserPreferencesController} (the durable per-user UI preferences surface),
 * with the REAL {@link PrincipalDomain} + {@link DomainRegistry} (multi-issuer) so the
 * domain handed to {@link UserPreferencesService} is derived from the validated
 * {@code iss}, not from a request param/body.
 *
 * <ul>
 *   <li>anonymous → 401 (GET + PUT), service never called;</li>
 *   <li>authenticated without {@code ROLE_USER} → 403, service never called;</li>
 *   <li>{@code ROLE_USER} brand-X → service scoped to owner==subject / domain "brandx";
 *       brand-Y → "brandy" (a brand-Y caller is never given a brand-X scope);</li>
 *   <li>PUT body carries only the preference key/value — owner + domain still come
 *       from the token; a {@code ?owner=} param is ignored;</li>
 *   <li>UNKNOWN issuer (non-SUPERADMIN) → fails closed to {@code "__deny__"};</li>
 *   <li>SUPERADMIN → {@code null} cross-domain bypass.</li>
 * </ul>
 */
@WebFluxTest(controllers = UserPreferencesController.class)
@Import({SecurityConfig.class, PrincipalDomain.class, DomainRegistry.class})
@TestPropertySource(properties = {
        "spring.security.oauth2.resourceserver.jwt.issuer-uri=",
        "app.tenancy.issuers=https://id.brandx.example=brandx,https://id.brandy.example=brandy"
})
class UserPreferencesControllerCrossDomainTest {

    private static final String BRANDX = "https://id.brandx.example";
    private static final String BRANDY = "https://id.brandy.example";

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean UserPreferencesService service;

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    @Test
    void get_anonymous_isUnauthorized_serviceNeverCalled() {
        client.get().uri("/bff/user/preferences").exchange().expectStatus().isUnauthorized();
        verify(service, never()).get(anyString(), any());
    }

    @Test
    void put_anonymous_isUnauthorized_serviceNeverCalled() {
        client.put().uri("/bff/user/preferences")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("key", "media.poison.default", "value", "balanced"))
                .exchange()
                .expectStatus().isUnauthorized();
        verify(service, never()).put(anyString(), anyString(), anyString(), any());
    }

    @Test
    void get_authenticatedWithoutRoleUser_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").issuer(BRANDX))
                        .authorities(authorities("DOMAIN_brandx")))
                .get().uri("/bff/user/preferences")
                .exchange()
                .expectStatus().isForbidden();
        verify(service, never()).get(anyString(), any());
    }

    @Test
    void get_brandX_scopedToBrandX_ownerIsSubject() {
        when(service.get(eq("alice"), eq("brandx"))).thenReturn(Mono.just(Map.of("a", "1")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").issuer(BRANDX))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                .get().uri(uri -> uri.path("/bff/user/preferences")
                        .queryParam("owner", "bob").build())   // spoofed owner param ignored
                .exchange()
                .expectStatus().isOk();

        verify(service).get("alice", "brandx");
        verify(service, never()).get(eq("bob"), any());
        verify(service, never()).get(anyString(), eq("brandy"));
    }

    @Test
    void get_brandY_scopedToBrandY_neverBrandX() {
        when(service.get(eq("carol"), eq("brandy"))).thenReturn(Mono.just(Map.of()));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("carol").issuer(BRANDY))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandy")))
                .get().uri("/bff/user/preferences")
                .exchange()
                .expectStatus().isOk();

        verify(service).get("carol", "brandy");
        verify(service, never()).get(anyString(), eq("brandx"));
    }

    @Test
    void put_brandX_ownerAndDomainFromToken_notBody() {
        when(service.put(eq("alice"), eq("media.poison.default"), eq("balanced"), eq("brandx")))
                .thenReturn(Mono.just(Map.of("media.poison.default", "balanced")));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("alice").issuer(BRANDX))
                        .authorities(authorities("ROLE_USER", "DOMAIN_brandx")))
                .put().uri("/bff/user/preferences")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("key", "media.poison.default", "value", "balanced"))
                .exchange()
                .expectStatus().isOk();

        verify(service).put("alice", "media.poison.default", "balanced", "brandx");
        verify(service, never()).put(anyString(), anyString(), anyString(), eq("brandy"));
    }

    @Test
    void get_unknownIssuer_failsClosedToDenySentinel() {
        when(service.get(eq("mallory"), eq("__deny__"))).thenReturn(Mono.just(Map.of()));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("mallory").issuer("https://evil.attacker.example"))
                        .authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/preferences")
                .exchange()
                .expectStatus().isOk();

        verify(service).get("mallory", "__deny__");
        verify(service, never()).get(eq("mallory"), eq("brandx"));
        verify(service, never()).get(eq("mallory"), eq("brandy"));
    }

    @Test
    void get_superadmin_nullCrossDomainBypass() {
        when(service.get(eq("root"), eq(null))).thenReturn(Mono.just(Map.of()));

        client.mutateWith(mockJwt()
                        .jwt(j -> j.subject("root").issuer(BRANDX).claim("roles", List.of("superadmin")))
                        .authorities(authorities("ROLE_USER", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                .get().uri("/bff/user/preferences")
                .exchange()
                .expectStatus().isOk();

        verify(service).get("root", null);
    }
}
