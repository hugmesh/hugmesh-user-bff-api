package systems.snapdragon.userbff.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import systems.snapdragon.userbff.security.DomainRegistry;
import systems.snapdragon.userbff.web.ApiException;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Owner-enforced CONNECTED APPS & DEVICES operations. EVERY method takes the owner
 * (the JWT subject, from the validated token) and operates ONLY on that owner's
 * clients:
 *
 * <ul>
 *   <li>{@link #list(String, String, String, Set)} — the owner's connected OAuth apps +
 *       device sessions, merged from the durable {@code connected_client_audit} rows +
 *       the live homeserver client-API read through the mTLS proxy (a GATED stub-seam,
 *       never hard-fail);</li>
 *   <li>{@link #revoke(String, String, String, Set)} — revoke one of the owner's
 *       clients: write the PER-CREDENTIAL gateway revocation key FIRST, then best-effort
 *       DELETE the homeserver device/app, then stamp {@code revoked_at} on the audit
 *       row. Owner-AND-id scoped so a caller can never revoke another user's client.</li>
 * </ul>
 *
 * <p>EXTERNAL-CLIENT-ROLE GATE (service leg / defence-in-depth): registering/using a
 * personal client requires the external-client role — a {@code matrix} client requires
 * {@code ROLE_MATRIX_EXTERNAL_CLIENT}, a {@code mastodon} client requires
 * {@code ROLE_MASTODON_EXTERNAL_CLIENT}. This is SEPARATE from the base
 * {@code ROLE_MATRIX}/{@code ROLE_MASTODON} (our-UI access): the external-client role
 * gates whether the user may register/use a NATIVE client through the gateway
 * passthrough. The caller's authorities are forwarded + re-checked here (the
 * controller's method-level {@code @PreAuthorize} is the API leg). Removing the role →
 * {@link #reconcilePersonalClientRevocation} revokes the user's personal-client tokens
 * WITHOUT affecting base-role our-UI access.
 */
@Service
public class ConnectedClientsService {

    private static final Logger log = LoggerFactory.getLogger(ConnectedClientsService.class);

    /** matrix client → required external-client role. */
    static final String ROLE_MATRIX_EXTERNAL_CLIENT = "ROLE_MATRIX_EXTERNAL_CLIENT";
    /** mastodon client → required external-client role. */
    static final String ROLE_MASTODON_EXTERNAL_CLIENT = "ROLE_MASTODON_EXTERNAL_CLIENT";

    private final ConnectedClientAuditRepository repo;
    private final Map<String, HomeserverClientsClient> clientsByPlatform;
    private final RevocationWriter revocations;

    public ConnectedClientsService(ConnectedClientAuditRepository repo,
                                   List<HomeserverClientsClient> homeserverClients,
                                   RevocationWriter revocations) {
        this.repo = repo;
        this.revocations = revocations;
        this.clientsByPlatform = new java.util.HashMap<>();
        for (HomeserverClientsClient c : homeserverClients) this.clientsByPlatform.put(c.platform(), c);
    }

    /**
     * The owner's connected apps + device sessions. The durable audit rows are the
     * floor; the live homeserver read (per platform the caller holds the external-client
     * role for, and only the gated/enabled seams) is merged best-effort on top. A user
     * with NO external-client role gets only their durable audit rows (no live read) —
     * they cannot drive a homeserver client-API read they're not entitled to.
     */
    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Flux<ConnectedClient> list(String owner, String localpart, String bearer,
                                      Set<String> callerRoles) {
        return list(owner, localpart, bearer, DomainRegistry.DEFAULT_DOMAIN, callerRoles);
    }

    public Flux<ConnectedClient> list(String owner, String localpart, String bearer, String domain,
                                      Set<String> callerRoles) {
        requireOwner(owner);
        Set<String> roles = callerRoles == null ? Set.of() : callerRoles;
        Flux<ConnectedClient> audited = repo.listForOwner(owner, domain);
        Flux<ConnectedClient> live = Flux.fromIterable(clientsByPlatform.values())
                .filter(c -> roles.contains(externalClientRoleFor(c.platform())))
                .flatMap(c -> c.list(localpart, bearer)
                        .onErrorResume(e -> {
                            log.warn("[connected-clients] best-effort {} live list for {} failed: {}",
                                    c.platform(), owner, e.toString());
                            return Flux.empty();
                        }));
        return audited.concatWith(live);
    }

    /**
     * Revoke one of the owner's connected clients (audit row id). Ordering (per the
     * design): (1) write the per-credential gateway revocation key FIRST (so the gateway
     * filter denies future use within ≤5s), (2) best-effort homeserver DELETE, (3) stamp
     * {@code revoked_at} on the audit row. The external-client role for the client's
     * platform is required (service leg). Owner-AND-id scoped (a 404 for a non-owner /
     * unknown / already-revoked id).
     */
    /** Back-compat overload — scopes to the platform {@code default} domain. */
    public Mono<Map<String, Object>> revoke(String owner, String id, String localpart, String bearer,
                                            Set<String> callerRoles) {
        return revoke(owner, id, localpart, bearer, DomainRegistry.DEFAULT_DOMAIN, callerRoles);
    }

    public Mono<Map<String, Object>> revoke(String owner, String id, String localpart, String bearer,
                                            String domain, Set<String> callerRoles) {
        requireOwner(owner);
        Set<String> roles = callerRoles == null ? Set.of() : callerRoles;
        return repo.find(owner, id, domain)
                .switchIfEmpty(Mono.error(ApiException.notFound("no such connected client for this user")))
                .flatMap(client -> {
                    if (!client.active()) {
                        return Mono.error(ApiException.notFound("connected client already revoked"));
                    }
                    ApiException forbidden = externalClientRoleForbidden(client.platform(), roles);
                    if (forbidden != null) {
                        return Mono.error(forbidden);
                    }
                    return revocations.revokeConnectedClient(client.platform(), localpart, client.externalRef())
                            .flatMap(keyWritten -> revokeUpstream(localpart, bearer, client)
                                    .flatMap(upstream -> repo.revoke(owner, id, domain)
                                            .map(stamped -> result(client, keyWritten, upstream, stamped))));
                });
    }

    /**
     * RECONCILE-on-role-removal seam: when the external-client role for a platform is
     * removed, revoke the user's PERSONAL-client tokens for that platform WITHOUT
     * affecting base-role our-UI access (writes {@code external-client:<localpart>:<platform>},
     * which the gateway filter checks only for {@code kind=personal} tokens). Best-effort
     * + never hard-fails. Exposed for the admin-bff/reconcile caller (documented seam).
     */
    public Mono<Boolean> reconcilePersonalClientRevocation(String platform, String localpart) {
        if (!ConnectedClient.validPlatform(platform)) {
            return Mono.error(ApiException.badRequest("platform must be matrix|mastodon"));
        }
        return revocations.revokePersonalClients(platform, localpart);
    }

    private Mono<Boolean> revokeUpstream(String localpart, String bearer, ConnectedClient client) {
        HomeserverClientsClient hs = clientsByPlatform.get(client.platform());
        if (hs == null) return Mono.just(false);
        return hs.revoke(localpart, client.externalRef(), bearer)
                .onErrorResume(e -> {
                    log.warn("[connected-clients] best-effort {} upstream revoke of {} for {} failed "
                                    + "(key + audit stamp stand): {}",
                            client.platform(), client.externalRef(), localpart, e.toString());
                    return Mono.just(false);
                });
    }

    /**
     * Service-leg external-client-role guard (defence-in-depth, mirrors the controller's
     * method-level {@code @PreAuthorize}). Returns a 403 when the caller lacks the
     * external-client role for the platform, else {@code null}:
     * <ul>
     *   <li>{@code matrix}   -> requires {@code ROLE_MATRIX_EXTERNAL_CLIENT};</li>
     *   <li>{@code mastodon} -> requires {@code ROLE_MASTODON_EXTERNAL_CLIENT}.</li>
     * </ul>
     */
    static ApiException externalClientRoleForbidden(String platform, Set<String> callerRoles) {
        Set<String> roles = callerRoles == null ? Set.of() : callerRoles;
        String required = externalClientRoleFor(platform);
        if (required != null && !roles.contains(required)) {
            return ApiException.forbidden(required + " required to manage a " + platform
                    + " personal client");
        }
        return null;
    }

    /** The external-client role required for a platform's native clients, or null. */
    static String externalClientRoleFor(String platform) {
        if ("matrix".equals(platform)) return ROLE_MATRIX_EXTERNAL_CLIENT;
        if ("mastodon".equals(platform)) return ROLE_MASTODON_EXTERNAL_CLIENT;
        return null;
    }

    private static Map<String, Object> result(ConnectedClient client, boolean keyWritten,
                                              boolean upstream, long stamped) {
        return Map.of(
                "revoked", stamped > 0,
                "id", client.id(),
                "platform", client.platform(),
                "revocationKey", keyWritten ? "written" : "stubbed",
                "upstream", upstream ? "live" : "stubbed");
    }

    private static void requireOwner(String owner) {
        if (owner == null || owner.isBlank()) {
            throw ApiException.unauthorized("missing authenticated subject");
        }
    }
}
