package systems.hugmesh.userbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;
import systems.hugmesh.userbff.security.PrincipalDomain;

import java.util.UUID;

/**
 * TEST/SEED-ONLY self-notify endpoint — {@code POST /bff/user/notifications/test-seed}.
 * Exists SOLELY so an e2e test, authenticated as an ordinary human persona (e.g.
 * {@code e2e-user}), can get a REAL {@code user_notifications} row created for ITSELF
 * without needing the {@code ROLE_SERVICE} client-credentials token that gates
 * {@link InternalNotificationController} (the actual production writer, driven by the
 * hugmesh-actions reconciler — unreachable from any browser session).
 *
 * <p><b>Not a parallel write path.</b> This controller does NOT touch the repository or
 * hand-write a row: it calls the EXACT SAME {@link InternalNotificationDeliveryService}
 * the production internal-deliver controller calls, so category-preference suppression,
 * the account-restriction forced-on rule, the SSE push, and the deterministic
 * insert-if-absent idempotency all behave identically to production. The only thing this
 * controller changes is WHO the deliver target is allowed to be.
 *
 * <p><b>No IDOR reopened.</b> {@link InternalNotificationController} is gated to
 * {@code ROLE_SERVICE} precisely because its target {@code (domain, userSubject)} comes
 * from the request body — a human reaching it could spoof a notification to ANY user.
 * This seed endpoint closes that hole the other way: target is NEVER taken from the
 * request, it is ALWAYS the caller's own {@code (JWT-issuer domain, JWT subject)} via
 * {@link PrincipalDomain} — the same self-only resolution {@link UserNotificationController}
 * uses for read/mark-read. A caller can seed a notification for themselves and nobody
 * else, so no cross-user write capability is introduced. Sits under the ordinary
 * {@code /bff/user/**} ROLE_USER floor (no new route class).
 *
 * <p><b>SHIPS DARK by default</b> — gated by {@code app.test-seed.enabled} (default
 * {@code false}), the same "ships dark behind a property" idiom as
 * {@code app.bff.oidc.enabled} ({@link systems.hugmesh.userbff.auth.SsoAuthController}).
 * When the flag is off the route still exists (so a misconfigured e2e run gets a loud,
 * honest 503 rather than a 404 that could be mistaken for "wrong path"), but it performs
 * NO write and reaches the delivery service ZERO times — never a silent no-op 200. Set
 * {@code TEST_SEED_ENABLED=true} only in the e2e/dev deployment profile; it MUST stay off
 * in production (it would let any authenticated user manufacture their own notification
 * rows, which is harmless to OTHER users but is still not a production-intended
 * capability).
 *
 * <p>{@code category} must be one of the real {@link NotificationCategory} vocabulary
 * (the same fail-closed 400 the production deliver path enforces) so seeded fixtures
 * exercise the real per-category preference/suppression logic. {@code sourceId} is
 * optional — pass the same value twice to prove insert-if-absent idempotency
 * ({@code deduped=true} on the second call); omitted, a fresh random id is used so
 * repeated seed calls in the same test always create a NEW row.
 */
@Tag(name = "Notifications (TEST-SEED, self only)", description = "TEST/SEED-ONLY. "
        + "Ships dark behind app.test-seed.enabled (default false). Creates a real "
        + "in-app notification for the CALLER ONLY via the same delivery service the "
        + "production ROLE_SERVICE internal-deliver path uses — never a parallel write.")
@RestController
@RequestMapping("/bff/user/notifications/test-seed")
@PreAuthorize("hasRole('USER')")
@Validated
public class TestSeedNotificationController {

    /** Fixed, bounded {@code sourceTable} token for every seed-created row — lets a
     *  human glance at {@code user_notifications.source_table} and know a row was
     *  test-seeded rather than delivered by the real reconciler. */
    static final String SEED_SOURCE_TABLE = "test-seed";

    private static final String DEFAULT_TITLE = "Test-seed notification";

    private final InternalNotificationDeliveryService service;
    private final PrincipalDomain principalDomain;
    private final boolean enabled;

    public TestSeedNotificationController(InternalNotificationDeliveryService service,
                                          PrincipalDomain principalDomain,
                                          @Value("${app.test-seed.enabled:false}") boolean enabled) {
        this.service = service;
        this.principalDomain = principalDomain;
        this.enabled = enabled;
    }

    /** The seed request. There is deliberately NO target field — the target is always
     *  the caller's own {@code (domain, JWT subject)}, never request-supplied. */
    public record SeedRequest(
            @NotBlank @Size(max = 64)
            @Pattern(regexp = "^[a-z][a-z-]{0,63}$",
                    message = "category must be a lower-alpha/hyphen token")
            String category,

            @Size(max = 512)
            String title,

            @Size(max = 100_000)
            String body,

            @Size(max = 128)
            @Pattern(regexp = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$",
                    message = "sourceId must be a bounded token")
            String sourceId) {}

    /** The seed outcome: the deterministic row id (so the caller can immediately drive
     *  mark-as-read against it) plus the same delivered/deduped/reason triple the
     *  production deliver path reports. */
    public record SeedResult(String id, boolean delivered, boolean deduped, String reason) {}

    @Operation(summary = "TEST/SEED-ONLY: create a real in-app notification for the "
            + "CALLING user (self only), through the production delivery service. "
            + "503 when app.test-seed.enabled=false (ships dark).")
    @PostMapping
    public Mono<SeedResult> seed(@AuthenticationPrincipal Jwt jwt,
                                 @RequestBody @Valid SeedRequest req) {
        if (!enabled) {
            // Honest disclosure: no bean toggle, no swallowed write — a real 503 so a
            // misconfigured e2e run FAILS instead of silently seeding nothing.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "test-seed is not enabled (app.test-seed.enabled=false)"));
        }
        String domain = principalDomain.forScope(jwt);
        if (domain == null) {
            // SUPERADMIN's cross-domain bypass has no single concrete domain to seed
            // into — refuse rather than guess one (fail-closed, not a silent default).
            return Mono.error(new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "test-seed requires a concrete domain; the caller's cross-domain "
                            + "SUPERADMIN principal has none — seed as a plain ROLE_USER persona"));
        }
        String owner = jwt.getSubject();
        String title = (req.title() == null || req.title().isBlank()) ? DEFAULT_TITLE : req.title();
        String sourceId = (req.sourceId() == null || req.sourceId().isBlank())
                ? UUID.randomUUID().toString() : req.sourceId();
        String id = StableNotificationId.forInApp(SEED_SOURCE_TABLE, sourceId);

        return service.deliver(domain, owner, req.category(), title, req.body(), SEED_SOURCE_TABLE, sourceId)
                .map(result -> new SeedResult(id, result.delivered(), result.deduped(), result.reason()));
    }
}
