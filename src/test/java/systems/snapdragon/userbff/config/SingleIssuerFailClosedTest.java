package systems.snapdragon.userbff.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.support.TestPropertySourceUtils;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.snapdragon.userbff.support.TestDatabaseConfig;
import systems.snapdragon.userbff.testsupport.TestIssuer;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * SINGLE-ISSUER fail-closed coverage — the PRODUCTION-DEFAULT resource-server path
 * proven END-TO-END through the REAL Boot-autoconfigured Nimbus decoder.
 *
 * <p><b>Why this exists (the known untested gap).</b> The existing
 * {@link MultiIssuerSecuritySliceTest} / {@link SecurityConfigPathGateSliceTest}
 * exercise the OPT-IN multi-issuer {@code tenantAuthManagerResolver} path
 * end-to-end, and {@link SingleIssuerModeSliceTest} unit-tests {@link
 * systems.snapdragon.commons.security.DomainRegistry} in single-issuer mode. But the
 * single-issuer branch of {@link SecurityConfig#resourceServer} — the plain
 * {@code o.jwt(...)} wiring that EVERY single-tenant cluster runs in production, and
 * the path the D6 (cookie / opaque-session bridge) + D8 (MFA challenge stamping)
 * changes will modify — has NEVER been driven through a REAL JWT decoder via {@code
 * WebTestClient}. A slice can't: {@code o.jwt()} with no explicit decoder relies on
 * Boot's {@code ReactiveOAuth2ResourceServerAutoConfiguration} to build the Nimbus
 * decoder from {@code issuer-uri} (with {@code JwtValidators.createDefaultWithIssuer},
 * the {@code iss}-binding validator). This is the only harness that proves that real
 * decoder fails CLOSED.
 *
 * <p>Boots the FULL context under {@code test} (so the active chain is {@code
 * devFilterChain}; its {@code commonRoutes()} {@code /bff/user/**} authenticated
 * floor + {@code anyExchange().authenticated()} are IDENTICAL to the prod chain, so
 * the fail-closed posture asserted here is the production posture). A single
 * in-process {@link TestIssuer} is the TRUSTED issuer-uri; a second {@link TestIssuer}
 * is a FOREIGN/unconfigured issuer. {@code app.tenancy.issuers} is left UNSET so
 * {@link systems.snapdragon.commons.security.DomainRegistry#isMultiIssuer()} is false
 * and the single-issuer {@code o.jwt(...)} branch is the one under test.
 *
 * <p>Assertions (the fail-closed contract the cookie/MFA work rides on):
 * <ol>
 *   <li><b>(a) valid configured issuer ACCEPTED</b> — a correctly-signed token from
 *       the one configured {@code issuer-uri} authenticates (200) and the Casdoor
 *       converter ran ({@code ROLE_USER} floor + {@code DOMAIN_default});</li>
 *   <li><b>(b) FOREIGN/unconfigured issuer REJECTED 401</b> — a perfectly-formed,
 *       correctly-signed token whose {@code iss} is a DIFFERENT issuer (its key not in
 *       the trusted JWKS, its iss not the configured one) is 401, NEVER silently
 *       accepted and NEVER treated as anonymous-allowed;</li>
 *   <li><b>(c) tampered signature -> 401</b>;</li>
 *   <li><b>(c') wrong-kid / unknown signing key -> 401</b> — a token claiming the
 *       TRUSTED {@code iss} but signed by a key whose {@code kid} is absent from the
 *       trusted JWKS cannot be verified -> 401 (a forged-key attack);</li>
 *   <li><b>(d) NO token on a gated path -> 401</b> — the authenticated() floor is
 *       fail-closed (not anonymous-allowed).</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: (a) USER-SITUATIONAL ALLOW;
 * (b)/(c)/(c')/(d) are CROSS-USER / unauthenticated DENY (the authentication boundary
 * — a foreign-issuer, tampered, wrong-key, or absent credential can never cross in).
 *
 * <p>NO live Casdoor and NO network egress beyond {@code 127.0.0.1}: the trusted
 * issuer is an in-process JWKS/OIDC server. Deterministic.
 */
@SpringBootTest
@AutoConfigureWebTestClient
@ActiveProfiles("test")
@Import({TestDatabaseConfig.class, SingleIssuerFailClosedTest.ProbeRoutes.class})
@ContextConfiguration(initializers = SingleIssuerFailClosedTest.TrustedIssuerInitializer.class)
class SingleIssuerFailClosedTest {

    /** The TRUSTED issuer — its issuer-uri is injected as the lone configured
     *  {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} so Boot's
     *  resource-server auto-config builds the REAL Nimbus decoder against it. Started
     *  by the initializer BEFORE the context refreshes (the decoder discovers the JWKS
     *  at startup). Shared across the test class; closed in {@link #stopIssuer()}. */
    private static final TestIssuer TRUSTED = new TestIssuer();

    /** A FOREIGN issuer — correctly stands up its own JWKS/OIDC, mints valid tokens,
     *  but is NOT the configured issuer-uri and is NOT in app.tenancy.issuers. Its
     *  token must fail closed. */
    private static final TestIssuer FOREIGN = new TestIssuer();

    @Autowired
    private WebTestClient client;

    @AfterAll
    static void stopIssuer() {
        TRUSTED.close();
        FOREIGN.close();
    }

    // ── (a) the lone configured issuer is ACCEPTED ────────────────────────────

    @Test
    void userSituational_configuredIssuerToken_isAccepted_andCasdoorConverterRan() {
        String token = TRUSTED.mint("user-1", List.of("admin"));
        client.get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("a token from the configured issuer-uri authenticates and the "
                                + "single-issuer Casdoor converter ran (ROLE_USER floor + "
                                + "DOMAIN_default for the single-tenant fallback)")
                        .contains("ROLE_USER")
                        .contains("ROLE_ADMIN")
                        .contains("DOMAIN_default"));
    }

    // ── (b) a FOREIGN / unconfigured issuer is REJECTED 401 (fail-closed) ──────

    @Test
    void crossUser_foreignIssuerToken_is401_failClosed_neverAccepted() {
        // FOREIGN mints a structurally-perfect, correctly-signed token. Its `iss` is
        // NOT the configured issuer-uri, so the single-issuer decoder's
        // createDefaultWithIssuer validator rejects it (and its signing key is not in
        // the trusted JWKS regardless). 401 — never a silent default-accept, never
        // anonymous-allowed. THIS is the load-bearing fail-closed guard the D6/D8
        // cookie+MFA changes ride on: if a future edit drops the issuer binding or
        // lets an unconfigured iss through, this turns red.
        String token = FOREIGN.mint("attacker", List.of("admin", "superadmin"));
        client.get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) tampered signature -> 401 ─────────────────────────────────────────

    @Test
    void crossUser_tamperedSignature_is401() {
        // A token from the TRUSTED issuer whose trailing signature bytes are corrupted
        // fails signature verification -> 401, not silently accepted.
        String token = TRUSTED.mint("user-1", List.of("admin"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c') wrong-kid / unknown signing key -> 401 ───────────────────────────

    @Test
    void crossUser_wrongKidUnknownSigningKey_is401() throws Exception {
        // A token claiming the TRUSTED issuer's `iss` (so it routes to the trusted
        // decoder) but signed by a FRESH RSA key whose `kid` is absent from the
        // trusted JWKS. The decoder can't find a matching verification key -> 401.
        // Guards against a decoder that ignores kid / accepts any signature for a
        // known issuer (a forged-key attack).
        String token = mintWithForeignKey(TRUSTED.issuerUri(), "forger");
        client.get().uri("/bff/user/_probe")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (d) no token on a gated path -> 401 (the authenticated() floor) ────────

    @Test
    void unauthenticated_noToken_onGatedPath_is401_notAnonymousAllowed() {
        client.get().uri("/bff/user/_probe")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Mint an RS256 JWT with the given {@code iss} but signed by a brand-new RSA key
     * whose random {@code kid} is NOT in any served JWKS — so no decoder can verify
     * it. Carries the Casdoor {@code roles} shape so that, were verification ever to
     * (wrongly) succeed, the assertion would still observe a non-401.
     */
    private static String mintWithForeignKey(String issuer, String subject) throws Exception {
        RSAKey foreignKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();
        Instant now = Instant.now();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("roles", List.of(java.util.Map.of("name", "superadmin")))
                .claim("name", subject)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(foreignKey.getKeyID()).build(),
                claims);
        jwt.sign(new RSASSASigner(foreignKey));
        return jwt.serialize();
    }

    /**
     * Starts {@link #TRUSTED} (already constructed as a static field) and injects its
     * issuer-uri as the lone configured {@code issuer-uri} BEFORE the context
     * refreshes — so {@code ReactiveOAuth2ResourceServerAutoConfiguration} builds the
     * real Nimbus decoder from it (single-issuer mode; {@code app.tenancy.issuers} is
     * deliberately left UNSET so the multi-issuer swap is NOT taken).
     */
    static class TrustedIssuerInitializer
            implements ApplicationContextInitializer<ConfigurableApplicationContext> {
        @Override
        public void initialize(ConfigurableApplicationContext applicationContext) {
            TestPropertySourceUtils.addInlinedPropertiesToEnvironment(
                    applicationContext,
                    "spring.security.oauth2.resourceserver.jwt.issuer-uri=" + TRUSTED.issuerUri());
        }
    }

    /**
     * Registers a FUNCTIONAL endpoint at the gated {@code /bff/user/_probe} path the
     * assertions hit — a {@code RouterFunction} bean (NOT an annotated
     * {@code @RestController}, which the app's component-scan would also pick up and
     * double-map). Echoes the authenticated principal's authorities so (a) can prove
     * the single-issuer Casdoor converter ran (ROLE_USER floor + DOMAIN_default).
     */
    @org.springframework.boot.test.context.TestConfiguration(proxyBeanMethods = false)
    static class ProbeRoutes {
        @org.springframework.context.annotation.Bean
        org.springframework.web.reactive.function.server.RouterFunction<
                org.springframework.web.reactive.function.server.ServerResponse> probeRoute() {
            return org.springframework.web.reactive.function.server.RouterFunctions.route()
                    .GET("/bff/user/_probe", req ->
                            org.springframework.security.core.context.ReactiveSecurityContextHolder.getContext()
                                    .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                                            .map(Object::toString)
                                            .collect(java.util.stream.Collectors.joining(",")))
                                    .defaultIfEmpty("ANONYMOUS")
                                    .flatMap(body ->
                                            org.springframework.web.reactive.function.server.ServerResponse
                                                    .ok().bodyValue(body)))
                    .build();
        }
    }
}
