package systems.snapdragon.userbff;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import systems.snapdragon.userbff.support.TestDatabaseConfig;

/**
 * Context-load smoke test: the full Spring context boots under the {@code test}
 * profile. application-test.yml excludes the Postgres R2DBC + Liquibase auto-config
 * (no live DB in CI); {@link TestDatabaseConfig} supplies an H2-PG-compat
 * ConnectionFactory + DatabaseClient + the real Liquibase changelog instead, so the
 * repositories + r2dbc-converters wire over a real (in-mem) schema. The Casdoor
 * account / external-block writes stay stubbed and the reactive JWT decoder is
 * mocked so no live Casdoor issuer is contacted. This proves all controllers,
 * services, repositories, clients, and the security + native-hints config wire
 * together.
 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestDatabaseConfig.class)
class UserBffApplicationContextTest {

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the
     *  oauth2 resource-server wiring is satisfied without a network call. */
    @MockitoBean ReactiveJwtDecoder reactiveJwtDecoder;

    @Test
    void contextLoads() {
        // success = the application context started with every bean wired.
    }
}
