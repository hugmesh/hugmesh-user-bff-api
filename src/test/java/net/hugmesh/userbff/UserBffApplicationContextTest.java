package net.hugmesh.userbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

/**
 * Context-load smoke test: the full Spring context boots under the {@code test}
 * profile. The {@link PostgresTestSupport} base wires R2DBC + Liquibase to a real
 * per-class Postgres container (Testcontainers), so the repositories + r2dbc-converters
 * wire over a real Liquibase-applied schema. The Casdoor account / external-block
 * writes stay stubbed and the reactive JWT decoder is mocked so no live Casdoor issuer
 * is contacted. This proves all controllers, services, repositories, clients, and the
 * security + native-hints config wire together.
 */
@SpringBootTest
@ActiveProfiles("test")
class UserBffApplicationContextTest extends PostgresTestSupport {

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the
     *  oauth2 resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void contextLoads() {
        // success = the application context started with every bean wired.
    }
}
