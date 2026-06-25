package systems.snapdragon.userbff.notification;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerSentEvent;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.PrincipalDomain;
import systems.snapdragon.userbff.web.ValidationPatterns;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeoutException;

/**
 * The in-app notification FLOOR inbox endpoint — the always-on in-app channel a user
 * can never silence (per-category prefs only gate the OTHER channels in later PRs). The
 * owner is ALWAYS the JWT subject; a user can only ever read/mark-read their OWN
 * notifications in their OWN brand. ROLE_USER floor + {@code @PreAuthorize}
 * defence-in-depth; domain-scoped (SUPERADMIN unscoped).
 *
 * <ul>
 *   <li>GET {@code /bff/user/notifications} — the caller's OWN in-app notifications,
 *       newest first, server-capped (the {@code limit} query param is bounded to
 *       {@link UserNotificationRepository#MAX_PAGE}).</li>
 *   <li>POST {@code /bff/user/notifications/{id}/read} — mark ONE of the caller's own
 *       notifications read. An id that is not the caller's own owner+domain row is a
 *       404 (no cross-user mark).</li>
 *   <li>GET {@code /bff/user/notifications/events} — real-time SSE stream of new
 *       notifications pushed immediately after DB write; 4-minute keepalive timeout
 *       signals the client to reconnect.</li>
 * </ul>
 *
 * <p>SHIPS DARK in PR1: there is no create endpoint — the snapdragon-actions reconciler
 * in a later PR is the only writer. This is the read/mark-read side only (intended).
 */
@Tag(name = "Notifications (in-app floor)", description = "The caller's OWN in-app "
        + "notifications (owner = JWT subject, domain-scoped). The always-on in-app "
        + "channel — read + mark-read only; the actions reconciler writes them.")
@RestController
@RequestMapping("/bff/user/notifications")
@PreAuthorize("hasRole('USER')")
@Validated
public class UserNotificationController {

    /** Default page size when the caller passes no {@code limit}. */
    private static final int DEFAULT_LIMIT = 50;

    /** SSE stream keepalive: client reconnects after this idle window. */
    private static final Duration SSE_TIMEOUT = Duration.ofMinutes(4);

    private final UserNotificationService service;
    private final PrincipalDomain principalDomain;
    private final SseNotificationBus sseBus;

    public UserNotificationController(UserNotificationService service,
                                      PrincipalDomain principalDomain,
                                      SseNotificationBus sseBus) {
        this.service = service;
        this.principalDomain = principalDomain;
        this.sseBus = sseBus;
    }

    @Operation(summary = "My in-app notifications (newest first, server-capped).")
    @GetMapping
    public Mono<List<UserNotification>> list(
            @AuthenticationPrincipal Jwt jwt,
            @RequestParam(name = "limit", defaultValue = "" + DEFAULT_LIMIT)
            @Min(1) @Max(UserNotificationRepository.MAX_PAGE) int limit) {
        return service.list(jwt.getSubject(), principalDomain.forScope(jwt), limit);
    }

    @Operation(summary = "Mark one of MY notifications read (404 if not my own row).")
    @PostMapping("/{id}/read")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public Mono<Void> markRead(
            @AuthenticationPrincipal Jwt jwt,
            @PathVariable
            @Pattern(regexp = ValidationPatterns.BLOCK_ID, message = "id must be a UUID")
            String id) {
        return service.markRead(id, jwt.getSubject(), principalDomain.forScope(jwt));
    }

    @Operation(summary = "Real-time notification event stream (SSE). Client reconnects on close.")
    @GetMapping(path = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public Flux<ServerSentEvent<SseNotificationEvent>> stream(
            @AuthenticationPrincipal Jwt jwt) {
        String userId = jwt.getSubject();
        return sseBus.subscribe(userId)
                // close after idle keepalive window — client EventSource reconnects automatically
                .timeout(SSE_TIMEOUT)
                .onErrorResume(TimeoutException.class, e -> Flux.empty())
                .map(ev -> ServerSentEvent.<SseNotificationEvent>builder(ev)
                        .id(ev.id())
                        .event(ev.category())
                        .build());
    }
}
