package net.hugmesh.userbff.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.userbff.config.SecurityConfig;
import net.hugmesh.userbff.hsproxy.HsTokenCustody;
import net.hugmesh.userbff.hsproxy.ServiceTokenBroker;
import net.hugmesh.userbff.web.ApiExceptionHandler;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * The FAIL-CLOSED half of {@link LegacyPathParityController}: with
 * {@code app.hs-token.enabled=false} the two provision legs 503 and NOTHING downstream is
 * touched — no admin-bff account read, no identity resolution, no mint. This is the one
 * documented divergence from admin-bff's {@code /bff/provision/*} (which has no feature gate),
 * and it mirrors {@code MatrixProxyController}/{@code MastodonProxyController} exactly rather
 * than inventing a fourth posture. It lives in its own slice because a
 * {@code @TestPropertySource} property cannot be flipped per-test inside one context.
 *
 * <p>{@code GET /bff/me/namespaces} is deliberately asserted UNAFFECTED by the gate: it reads
 * account grants, it brokers nothing, and admin-bff has no gate on it either.
 */
@WebFluxTest(controllers = LegacyPathParityController.class)
@Import({SecurityConfig.class, CanonicalIdentityResolver.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.hs-token.enabled=false")
class LegacyPathParityControllerDarkTest {

    private static final String ACCOUNT_ID = "google:alice@example.test";

    @Autowired ApplicationContext context;
    WebTestClient client;

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean AdminBffInternalClient adminBff;
    @MockitoBean HsTokenCustody custody;
    @MockitoBean ServiceTokenBroker broker;

    @BeforeEach
    void setUp() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private static Collection<GrantedAuthority> authorities(String... names) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String n : names) {
            out.add(new SimpleGrantedAuthority(n));
        }
        return out;
    }

    @Test
    void provisionMatrix_featureDark_is503_andNothingDownstreamIsTouched() {
        client.mutateWith(mockJwt().jwt(j -> j.subject(ACCOUNT_ID).claim("localpart", "alice.example"))
                        .authorities(authorities("ROLE_USER", "ROLE_MATRIX")))
                .post().uri("/bff/provision/matrix")
                .exchange()
                .expectStatus().isEqualTo(503);
        verify(adminBff, never()).getAccount(anyString());
        verify(broker, never()).mintMatrix(anyString(), anyString());
    }

    @Test
    void provisionMastodon_featureDark_is503_andNothingDownstreamIsTouched() {
        client.mutateWith(mockJwt().jwt(j -> j.subject(ACCOUNT_ID).claim("mastodon_localpart", "alice_example"))
                        .authorities(authorities("ROLE_USER", "ROLE_MASTODON")))
                .post().uri("/bff/provision/mastodon")
                .exchange()
                .expectStatus().isEqualTo(503);
        verify(adminBff, never()).getAccount(anyString());
        verify(broker, never()).mintMastodon(anyString(), anyString());
    }

    /** The namespaces read brokers nothing, so the hs-token gate must not reach it. */
    @Test
    void namespaces_isUnaffectedByTheHsTokenGate() {
        org.mockito.Mockito.when(adminBff.accountNamespaces(ACCOUNT_ID))
                .thenReturn(reactor.core.publisher.Mono.just(List.of("wiki")));

        client.mutateWith(mockJwt().jwt(j -> j.subject(ACCOUNT_ID))
                        .authorities(authorities("ROLE_USER")))
                .get().uri("/bff/me/namespaces")
                .exchange()
                .expectStatus().isOk()
                .expectBody().json("{\"namespaces\":[\"wiki\"]}");
    }
}
