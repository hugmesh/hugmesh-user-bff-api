package net.hugmesh.userbff.session;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.userbff.auth.CanonicalIdentityResolver;
import net.hugmesh.userbff.config.BffSessionAuthenticationWebFilter;
import net.hugmesh.userbff.session.SessionsInternalClient.BffSessionWire;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * The "active session management" service: lists / revokes the CALLER'S OWN opaque
 * {@code bff_} sessions, delegating the actual session data to admin-bff (which owns the
 * {@code bff_session} table) over {@link SessionsInternalClient}.
 *
 * <p><b>Cross-user isolation is enforced SERVER-SIDE here</b>, never by the controller's
 * inputs:
 * <ul>
 *   <li>the caller's {@code account_id} is DERIVED from the validated JWT principal via
 *       {@link #accountIdFromJwt(Jwt)} — the caller's OWN account id, keyed exactly as
     *       admin-bff persists it: the bff_ synthetic principal's {@code sub} verbatim (it IS
     *       {@code provider:handle} for every provider), else -- for a real Casdoor JWT --
     *       {@code casdoor:<subject>} via {@link CanonicalIdentityResolver#ownAccountId(Jwt)}
     *       (subject = first non-blank of {email, preferred_username, sub}; {@code AccountStore.idFor}
     *       = {@code provider + ":" + handle.toLowerCase()}). This is a claim-derived OWN key, NEVER
     *       the old email-to-google:/preferred_username-to-discord: cross-namespace guess (which could
     *       resolve ANOTHER user's invite account). admin-bff stores exactly that string
     *       in {@code bff_session.account_id}, so a list scoped to it returns ONLY the caller's
     *       rows. The account is NEVER taken from a request param/body/header.</li>
 *   <li>on revoke the target {@code id} is validated to belong to the caller by re-listing
 *       the caller's own sessions and matching the opaque fingerprint; a non-matching id is
 *       a generic 404 (anti-enumeration — never reveals whether the id exists for another
 *       account).</li>
 * </ul>
 *
 * <p>The opaque {@code id} exposed to the browser is a SHA-256 fingerprint of the raw
 * {@code bff_} token (never the raw token — that is a live bearer credential). The raw token
 * is resolved back from the fingerprint ONLY over the caller's own live tokens, so it never
 * leaves the server and an id the caller does not own can never resolve.
 */
@Service
public class SessionsService {

    private final SessionsInternalClient sessions;

    public SessionsService(SessionsInternalClient sessions) {
        this.sessions = sessions;
    }

    /**
     * List the caller's OWN active sessions as caller-safe views (opaque id + lifecycle
     * timestamps). The account is derived from the JWT server-side; admin-bff returns only
     * the rows for that account.
     */
    public Flux<UserSession> listMine(Jwt jwt) {
        String accountId = accountIdFromJwt(jwt);
        return sessions.sessionsForAccount(accountId).map(SessionsService::toUserSession);
    }

    /**
     * Revoke ONE of the caller's own sessions, addressed by its opaque {@code id}. Re-lists
     * the caller's own sessions (scoped to the JWT-derived account) and matches the id to a
     * raw token; a non-matching id is a generic 404 (anti-enumeration). Revoking the caller's
     * own CURRENT session is allowed (logout-this-device). The raw token is handed to
     * admin-bff's idempotent internal revoke and never returned to the browser.
     */
    public Mono<Void> revokeMine(Jwt jwt, String id) {
        String accountId = accountIdFromJwt(jwt);
        // Re-list the caller's OWN sessions and find the raw token whose fingerprint matches
        // the requested id. Because the list is account-scoped server-side, an id belonging
        // to another account can never be found here — so cross-user revoke is structurally
        // impossible, not merely checked.
        return sessions.sessionsForAccount(accountId)
                .filter(row -> fingerprint(row.token()).equals(id))
                .next()
                .switchIfEmpty(Mono.error(ApiException.notFound("no such session")))
                .flatMap(row -> sessions.deleteSession(row.token()));
    }

    /**
     * Derive the caller's {@code bff_session.account_id} from the validated JWT.
     *
     * <p><b>Native-login (the live path):</b> the principal is the SYNTHETIC {@link Jwt}
     * built by {@link BffSessionAuthenticationWebFilter} for a {@code bff_} session, whose
     * {@code sub} IS the admin-bff account id ({@code provider:handle}, e.g.
     * {@code casdoor:<uuid>}) — the EXACT value {@code AccountStore.newSession} writes into
     * {@code bff_session.account_id}. Use it directly, recognised by the synthetic token's
     * marker ({@link BffSessionAuthenticationWebFilter#SYNTHETIC_TOKEN_MARKER}). Before this,
     * a casdoor-provider account fell through to the {@code preferred_username} branch below
     * and was mis-derived as a nonexistent {@code discord:<handle>} id, so
     * {@code /bff/user/sessions} listed NONE of the caller's real sessions (live: {@code
     * 200 []} despite admin-bff holding rows for {@code casdoor:<uuid>}) and revoke 404'd —
     * the whole active-session-management surface was silently dead for native login.
     *
     * <p><b>Real Casdoor JWT (a genuine resource-server token presented directly):</b>
     * resolves the caller's OWN account id via {@link CanonicalIdentityResolver#ownAccountId(Jwt)}
     * -- {@code casdoor:<subject>}, subject = first non-blank of {email, preferred_username, sub}
     * (mirroring admin-bff's {@code InternalAccountController.subjectFromIdToken} +
     * {@code AccountStore.idFor(provider, handle) = provider + ":" + handle.toLowerCase()}). For a
     * native-Casdoor account the stored id is {@code casdoor:<subject>}, NOT google:/discord:<handle>:
     * the OLD email-to-google:/preferred_username-to-discord: guess both MISSED the caller's own
     * sessions AND could resolve ANOTHER user's discord:<handle> account (a cross-user session
     * enumerate/force-revoke), so it is DELETED. No usable subject claim ==> 401 (the principal can't
     * own a session).
     */
    static String accountIdFromJwt(Jwt jwt) {
        // Native-login synthetic principal: sub is already the full account id — use verbatim.
        String tokenValue = jwt.getTokenValue();
        if (tokenValue != null && tokenValue.startsWith(BffSessionAuthenticationWebFilter.SYNTHETIC_TOKEN_MARKER)) {
            String subject = jwt.getSubject();
            if (subject != null && !subject.isBlank()) {
                return subject;
            }
            // A synthetic principal with no subject is a filter-internal bug, not a caller
            // condition — fail closed rather than fall through to the JWT-claim derivation
            // (which would mis-map it to a wrong or nonexistent account).
            throw ApiException.unauthorized("no account identity in session principal");
        }
        // A REAL Casdoor JWT presented directly (not the synthetic principal above): resolve the
        // caller's OWN account id the SAME way admin-bff keyed it -- casdoor:<subject>, subject =
        // first non-blank of {email, preferred_username, sub} (CanonicalIdentityResolver.ownAccountId,
        // mirroring admin-bff's InternalAccountController.subjectFromIdToken + AccountStore.idFor).
        //
        // This DELETES the old email->google:<lc> / preferred_username->discord:<lc> guess, which was
        // the SAME cross-namespace hole the six mint sites closed: for a native-Casdoor account the id
        // is casdoor:<subject>, never google:/discord:<handle>, so the guess both MISSED the caller's
        // own sessions AND could resolve ANOTHER user's discord:<handle> account -- letting a caller
        // enumerate/force-revoke the victim's bff_ sessions by presenting the victim's handle as
        // preferred_username. Fail closed (401) only when the token carries no usable subject at all.
        String ownId = CanonicalIdentityResolver.ownAccountId(jwt);
        if (ownId != null) {
            return ownId;
        }
        throw ApiException.unauthorized("no account identity in token (email/preferred_username/sub absent)");
    }

    /** Project an admin-bff wire row to the caller-safe view (opaque id, no raw token). */
    private static UserSession toUserSession(BffSessionWire row) {
        return new UserSession(fingerprint(row.token()), row.createdAt(), row.expiresAt());
    }

    /**
     * The opaque, deterministic fingerprint of a raw {@code bff_} token = its SHA-256 hex
     * digest. Safe to expose to a browser (a one-way digest of a high-entropy random token
     * is not reversible to the credential) and stable, so the same session yields the same
     * id across list calls and the revoke handle matches.
     */
    static String fingerprint(String rawToken) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] digest = sha256.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated on every JVM (JLS / JCA standard names) — unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
