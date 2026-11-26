package net.hugmesh.userbff.directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.userbff.auth.AdminBffInternalClient;
import net.hugmesh.userbff.auth.AdminBffInternalClient.MeshUserView;
import net.hugmesh.userbff.security.PrincipalDomain;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The member directory's trust boundary in user-bff: the scope it forwards comes from the caller's VALIDATED
 * JWT and nothing the browser sends; a plain member is forwarded as their own domain, a SUPERADMIN as the
 * unscoped flag, an unresolved issuer as the non-matchable sentinel (admin-bff then fails closed); and the
 * per-subject rate limit answers 429 instead of reaching admin-bff.
 */
class MemberDirectoryControllerTest {

    static final DomainRegistry MULTI = new DomainRegistry(
            "https://id.brandx.example",
            "https://id.brandx.example=brandx,https://id.brandy.example=brandy");

    AdminBffInternalClient admin;
    MemberDirectoryController controller;

    @BeforeEach
    void setUp() {
        admin = mock(AdminBffInternalClient.class);
        when(admin.searchMeshUsers(any(), anyBoolean(), anyString(), anyInt()))
                .thenReturn(Mono.just(List.of(new MeshUserView("alice", "alice", "brandx"))));
        controller = new MemberDirectoryController(admin, new PrincipalDomain(MULTI), new DirectoryRateLimiter());
    }

    private static String any() {
        return org.mockito.ArgumentMatchers.any();
    }

    private static Jwt jwt(String issuer, String sub, Object roles) {
        Jwt.Builder b = Jwt.withTokenValue("t").header("alg", "none").subject(sub)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600));
        if (issuer != null) b = b.claim("iss", issuer).issuer(issuer);
        if (roles != null) b = b.claim("roles", roles);
        return b.build();
    }

    @Test
    void a_member_is_forwarded_as_their_own_domain_and_never_as_a_superadmin() {
        StepVerifier.create(controller.search(jwt("https://id.brandx.example", "u1", List.of("user")), "ali", 10))
                .expectNextCount(1).verifyComplete();
        verify(admin).searchMeshUsers("brandx", false, "ali", 10);
    }

    @Test
    void another_domains_member_is_forwarded_as_that_other_domain() {
        StepVerifier.create(controller.search(jwt("https://id.brandy.example", "u2", List.of("user")), "ali", 10))
                .expectNextCount(1).verifyComplete();
        verify(admin).searchMeshUsers("brandy", false, "ali", 10);
    }

    @Test
    void a_superadmin_is_forwarded_unscoped() {
        StepVerifier.create(controller.search(jwt("https://id.brandx.example", "root", List.of("superadmin", "user")), "ali", 10))
                .expectNextCount(1).verifyComplete();
        verify(admin).searchMeshUsers(isNull(), eq(true), eq("ali"), eq(10));
    }

    @Test
    void an_unresolved_issuer_is_forwarded_as_the_deny_sentinel_not_as_unscoped() {
        StepVerifier.create(controller.search(jwt("https://evil.example", "u3", List.of("user")), "ali", 10))
                .expectNextCount(1).verifyComplete();
        verify(admin).searchMeshUsers("__deny__", false, "ali", 10);
        verify(admin, never()).searchMeshUsers(isNull(), eq(true), anyString(), anyInt());
    }

    @Test
    void past_the_rate_limit_the_answer_is_429_and_admin_bff_is_not_called() {
        Jwt who = jwt("https://id.brandx.example", "busy", List.of("user"));
        for (int i = 0; i < DirectoryRateLimiter.MAX_REQUESTS; i++) {
            StepVerifier.create(controller.search(who, "ali", 10)).expectNextCount(1).verifyComplete();
        }
        StepVerifier.create(controller.search(who, "ali", 10))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ResponseStatusException.class);
                    assertThat(((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
                }).verify();
        verify(admin, org.mockito.Mockito.times(DirectoryRateLimiter.MAX_REQUESTS))
                .searchMeshUsers(anyString(), anyBoolean(), anyString(), anyInt());
    }

    @Test
    void the_limit_is_per_subject_and_the_window_slides() {
        long[] now = {0};
        Clock clock = new Clock() {
            public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(java.time.ZoneId z) { return this; }
            public Instant instant() { return Instant.ofEpochMilli(now[0]); }
            public long millis() { return now[0]; }
        };
        DirectoryRateLimiter l = new DirectoryRateLimiter(clock);
        for (int i = 0; i < DirectoryRateLimiter.MAX_REQUESTS; i++) assertThat(l.tryAcquire("a")).isTrue();
        assertThat(l.tryAcquire("a")).as("31st in the window").isFalse();
        assertThat(l.tryAcquire("b")).as("another subject is unaffected").isTrue();
        now[0] += DirectoryRateLimiter.WINDOW_MILLIS + 1;
        assertThat(l.tryAcquire("a")).as("the window slid").isTrue();
    }
}
