package systems.snapdragon.userbff.client;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.config.SecurityConfig;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;

/**
 * METHOD-LEVEL {@code @PreAuthorize} (API leg) test for the EXTERNAL-CLIENT-ROLE gate
 * on {@link ConnectedClientsController}, driven through {@link WebTestClient} with
 * synthetic authentications. Proves the gate denies at the HTTP boundary BEFORE the
 * service is even called, and that EITHER external-client role admits the caller to
 * the surface (the per-platform check is then the service leg):
 * <ul>
 *   <li>no external-client role (ROLE_USER only) -> 403 on GET + DELETE (service never invoked);</li>
 *   <li>base ROLE_MATRIX (our-UI access) alone is NOT enough -> 403 (external-client is SEPARATE);</li>
 *   <li>ROLE_MATRIX_EXTERNAL_CLIENT -> reaches the service;</li>
 *   <li>ROLE_MASTODON_EXTERNAL_CLIENT -> reaches the service.</li>
 * </ul>
 */
@WebFluxTest(controllers = ConnectedClientsController.class)
@Import(SecurityConfig.class)
class ConnectedClientsControllerGateTest {

    @Autowired WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean ConnectedClientsService clients;

    private static final String ID = UUID.randomUUID().toString();

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) out.add(new SimpleGrantedAuthority(n));
        return out;
    }

    // ── no external-client role → 403, service never called ──────────────────

    @Test
    void list_withoutExternalClientRole_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .get().uri("/bff/user/connected-clients")
                .exchange()
                .expectStatus().isForbidden();
        verify(clients, never()).list(anyString(), anyString(), any(), any(), any());
    }

    @Test
    void revoke_withoutExternalClientRole_isForbidden_serviceNeverCalled() {
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER")))
                .delete().uri("/bff/user/connected-clients/" + ID)
                .exchange()
                .expectStatus().isForbidden();
        verify(clients, never()).revoke(anyString(), anyString(), anyString(), any(), any(), any());
    }

    @Test
    void baseMatrixRoleAlone_isNotEnough_isForbidden() {
        // base ROLE_MATRIX = our-UI access; the external-client role is SEPARATE.
        client.mutateWith(mockJwt().authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .get().uri("/bff/user/connected-clients")
                .exchange()
                .expectStatus().isForbidden();
        verify(clients, never()).list(anyString(), anyString(), any(), any(), any());
    }

    // ── with an external-client role → reaches the service ───────────────────

    @Test
    void list_withMatrixExternalClientRole_reachesService() {
        when(clients.list(anyString(), anyString(), any(), any(), any())).thenReturn(Flux.empty());
        client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX_EXTERNAL_CLIENT")))
                .get().uri("/bff/user/connected-clients")
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void revoke_withMastodonExternalClientRole_reachesService() {
        when(clients.revoke(anyString(), anyString(), anyString(), any(), any(), any()))
                .thenReturn(Mono.just(Map.of("revoked", true)));
        client.mutateWith(mockJwt().jwt(j -> j.subject("bob"))
                        .authorities(authorities("ROLE_USER", "ROLE_MASTODON_EXTERNAL_CLIENT")))
                .delete().uri("/bff/user/connected-clients/" + ID)
                .exchange()
                .expectStatus().isOk();
    }
}
